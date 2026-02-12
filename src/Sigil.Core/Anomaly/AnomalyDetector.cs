using System.Globalization;
using Sigil.Signing;

namespace Sigil.Anomaly;

public static class AnomalyDetector
{
    public static AnomalyReport Detect(SignatureEnvelope envelope, BaselineModel baseline)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(baseline);

        var findings = new List<AnomalyFinding>();

        foreach (var entry in envelope.Signatures)
        {
            DetectUnknownSigner(entry, baseline, findings);
            DetectUnknownOidc(entry, baseline, findings);
            DetectOffHours(entry, baseline, findings);
            DetectUnknownAlgorithm(entry, baseline, findings);
            DetectUnknownLabel(entry, baseline, findings);
        }

        return new AnomalyReport
        {
            ArtifactName = envelope.Subject.Name,
            Timestamp = DateTimeOffset.UtcNow,
            Findings = findings
        };
    }

    private static void DetectUnknownSigner(
        SignatureEntry entry,
        BaselineModel baseline,
        List<AnomalyFinding> findings)
    {
        if (baseline.Signers.ContainsKey(entry.KeyId))
            return;

        foreach (var allowedSigner in baseline.Allowlist.Signers)
        {
            if (string.Equals(allowedSigner, entry.KeyId, StringComparison.Ordinal))
                return;
        }

        findings.Add(new AnomalyFinding
        {
            RuleName = "UnknownSigner",
            Severity = baseline.Thresholds.NewSignerSeverity,
            Message = $"Signer {entry.KeyId} is not in the baseline",
            Context = new Dictionary<string, string> { ["keyId"] = entry.KeyId }
        });
    }

    private static void DetectUnknownOidc(
        SignatureEntry entry,
        BaselineModel baseline,
        List<AnomalyFinding> findings)
    {
        if (entry.OidcIssuer is null)
            return;

        var issuer = entry.OidcIssuer;
        var identity = entry.OidcIdentity ?? string.Empty;

        // Check allowlist first
        foreach (var allowed in baseline.Allowlist.OidcIdentities)
        {
            if (string.Equals(allowed, identity, StringComparison.Ordinal))
                return;
        }

        if (!baseline.OidcIdentities.TryGetValue(issuer, out var knownIdentities))
        {
            findings.Add(new AnomalyFinding
            {
                RuleName = "UnknownOidcIdentity",
                Severity = baseline.Thresholds.UnknownOidcSeverity,
                Message = $"Unknown OIDC issuer: {issuer}",
                Context = new Dictionary<string, string>
                {
                    ["oidcIssuer"] = issuer,
                    ["oidcIdentity"] = identity
                }
            });
            return;
        }
        bool identityKnown = false;
        foreach (var known in knownIdentities)
        {
            if (string.Equals(known, identity, StringComparison.Ordinal))
            {
                identityKnown = true;
                break;
            }
        }

        if (!identityKnown)
        {
            findings.Add(new AnomalyFinding
            {
                RuleName = "UnknownOidcIdentity",
                Severity = baseline.Thresholds.UnknownOidcSeverity,
                Message = $"Unknown OIDC identity: {identity} for issuer {issuer}",
                Context = new Dictionary<string, string>
                {
                    ["oidcIssuer"] = issuer,
                    ["oidcIdentity"] = identity
                }
            });
        }
    }

    private static void DetectOffHours(
        SignatureEntry entry,
        BaselineModel baseline,
        List<AnomalyFinding> findings)
    {
        if (!DateTimeOffset.TryParse(entry.Timestamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
            return;

        int hour = dto.UtcDateTime.Hour;

        if (baseline.SigningHours.Contains(hour))
            return;

        foreach (var allowedHour in baseline.Allowlist.Hours)
        {
            if (allowedHour == hour)
                return;
        }

        findings.Add(new AnomalyFinding
        {
            RuleName = "OffHoursSigning",
            Severity = baseline.Thresholds.OffHoursSeverity,
            Message = $"Signing occurred at hour {hour} UTC, outside baseline hours",
            Context = new Dictionary<string, string>
            {
                ["hour"] = hour.ToString(CultureInfo.InvariantCulture),
                ["timestamp"] = entry.Timestamp
            }
        });
    }

    private static void DetectUnknownAlgorithm(
        SignatureEntry entry,
        BaselineModel baseline,
        List<AnomalyFinding> findings)
    {
        foreach (var known in baseline.Algorithms)
        {
            if (string.Equals(known, entry.Algorithm, StringComparison.Ordinal))
                return;
        }

        findings.Add(new AnomalyFinding
        {
            RuleName = "UnknownAlgorithm",
            Severity = baseline.Thresholds.UnknownAlgorithmSeverity,
            Message = $"Algorithm {entry.Algorithm} is not in the baseline",
            Context = new Dictionary<string, string> { ["algorithm"] = entry.Algorithm }
        });
    }

    private static void DetectUnknownLabel(
        SignatureEntry entry,
        BaselineModel baseline,
        List<AnomalyFinding> findings)
    {
        if (entry.Label is null)
            return;

        foreach (var known in baseline.Labels)
        {
            if (string.Equals(known, entry.Label, StringComparison.Ordinal))
                return;
        }

        foreach (var allowed in baseline.Allowlist.Labels)
        {
            if (string.Equals(allowed, entry.Label, StringComparison.Ordinal))
                return;
        }

        findings.Add(new AnomalyFinding
        {
            RuleName = "UnknownLabel",
            Severity = baseline.Thresholds.UnknownLabelSeverity,
            Message = $"Label '{entry.Label}' is not in the baseline",
            Context = new Dictionary<string, string> { ["label"] = entry.Label }
        });
    }
}
