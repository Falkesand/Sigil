using System.Globalization;
using Sigil.Signing;

namespace Sigil.Anomaly;

public static class BaselineLearner
{
    public static AnomalyResult<BaselineModel> Learn(IReadOnlyList<SignatureEnvelope> envelopes)
    {
        ArgumentNullException.ThrowIfNull(envelopes);

        var signerCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var signerAlgorithms = new Dictionary<string, string>(StringComparer.Ordinal);
        var signerLastSeen = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        var oidcIdentities = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var signingHours = new HashSet<int>();
        var algorithms = new HashSet<string>(StringComparer.Ordinal);
        var labels = new HashSet<string>(StringComparer.Ordinal);
        var sampleCount = 0;

        foreach (var envelope in envelopes)
        {
            foreach (var entry in envelope.Signatures)
            {
                sampleCount++;

                var keyId = entry.KeyId;

                if (signerCounts.TryGetValue(keyId, out var count))
                {
                    signerCounts[keyId] = count + 1;
                }
                else
                {
                    signerCounts[keyId] = 1;
                }

                signerAlgorithms[keyId] = entry.Algorithm;

                if (DateTimeOffset.TryParse(entry.Timestamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts))
                {
                    if (!signerLastSeen.TryGetValue(keyId, out var existing) || ts > existing)
                    {
                        signerLastSeen[keyId] = ts;
                    }

                    signingHours.Add(ts.UtcDateTime.Hour);
                }

                if (entry.OidcIssuer is not null && entry.OidcIdentity is not null)
                {
                    if (!oidcIdentities.TryGetValue(entry.OidcIssuer, out var identitySet))
                    {
                        identitySet = new HashSet<string>(StringComparer.Ordinal);
                        oidcIdentities[entry.OidcIssuer] = identitySet;
                    }

                    identitySet.Add(entry.OidcIdentity);
                }

                algorithms.Add(entry.Algorithm);

                if (entry.Label is not null)
                {
                    labels.Add(entry.Label);
                }
            }
        }

        var signers = new Dictionary<string, SignerInfo>(StringComparer.Ordinal);
        foreach (var kvp in signerCounts)
        {
            signers[kvp.Key] = new SignerInfo
            {
                Count = kvp.Value,
                Algorithm = signerAlgorithms[kvp.Key],
                LastSeen = signerLastSeen.GetValueOrDefault(kvp.Key)
            };
        }

        var oidcDict = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var kvp in oidcIdentities)
        {
            oidcDict[kvp.Key] = kvp.Value.OrderBy(v => v, StringComparer.Ordinal).ToList();
        }

        var now = DateTimeOffset.UtcNow;

        var model = new BaselineModel
        {
            Version = "1.0",
            Kind = "anomaly-baseline",
            CreatedAt = now,
            UpdatedAt = now,
            SampleCount = sampleCount,
            Signers = signers,
            OidcIdentities = oidcDict,
            SigningHours = signingHours.OrderBy(h => h).ToList(),
            Algorithms = algorithms.OrderBy(a => a, StringComparer.Ordinal).ToList(),
            Labels = labels.OrderBy(l => l, StringComparer.Ordinal).ToList(),
            Allowlist = new AllowlistConfig(),
            Thresholds = new ThresholdConfig()
        };

        return AnomalyResult<BaselineModel>.Ok(model);
    }
}
