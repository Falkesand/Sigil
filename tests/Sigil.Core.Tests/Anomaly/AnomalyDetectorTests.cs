using Sigil.Anomaly;
using Sigil.Signing;

namespace Sigil.Core.Tests.Anomaly;

public class AnomalyDetectorTests
{
    // ── Unknown Signer ──────────────────────────────────────────────

    [Fact]
    public void Known_signer_produces_no_finding()
    {
        var envelope = CreateEnvelope(keyId: "sha256:known");
        var baseline = CreateBaseline(signerKeys: ["sha256:known"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownSigner");
    }

    [Fact]
    public void Unknown_signer_produces_warning()
    {
        var envelope = CreateEnvelope(keyId: "sha256:unknown");
        var baseline = CreateBaseline(signerKeys: ["sha256:known"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "UnknownSigner");
        Assert.Equal(AnomalySeverity.Warning, finding.Severity);
        Assert.Contains("sha256:unknown", finding.Message);
        Assert.Equal("sha256:unknown", finding.Context!["keyId"]);
    }

    [Fact]
    public void Allowlisted_signer_is_suppressed()
    {
        var envelope = CreateEnvelope(keyId: "sha256:newkey");
        var baseline = CreateBaseline(
            signerKeys: ["sha256:known"],
            allowlist: new AllowlistConfig { Signers = ["sha256:newkey"] });

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownSigner");
    }

    [Fact]
    public void Multiple_signatures_all_known_no_findings()
    {
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test-artifact",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key1", Algorithm = "ecdsa-p256", PublicKey = "dGVzdA==",
                    Value = "c2ln", Timestamp = "2026-02-10T14:30:00Z"
                },
                new SignatureEntry
                {
                    KeyId = "sha256:key2", Algorithm = "ecdsa-p256", PublicKey = "dGVzdA==",
                    Value = "c2ln", Timestamp = "2026-02-10T14:30:00Z"
                }
            ]
        };
        var baseline = CreateBaseline(signerKeys: ["sha256:key1", "sha256:key2"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownSigner");
    }

    [Fact]
    public void Multiple_signatures_one_unknown_one_finding()
    {
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test-artifact",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key1", Algorithm = "ecdsa-p256", PublicKey = "dGVzdA==",
                    Value = "c2ln", Timestamp = "2026-02-10T14:30:00Z"
                },
                new SignatureEntry
                {
                    KeyId = "sha256:unknown", Algorithm = "ecdsa-p256", PublicKey = "dGVzdA==",
                    Value = "c2ln", Timestamp = "2026-02-10T14:30:00Z"
                }
            ]
        };
        var baseline = CreateBaseline(signerKeys: ["sha256:key1"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        var signerFindings = report.Findings.Where(f => f.RuleName == "UnknownSigner").ToList();
        Assert.Single(signerFindings);
        Assert.Contains("sha256:unknown", signerFindings[0].Message);
    }

    [Fact]
    public void Custom_signer_severity_threshold_applied()
    {
        var envelope = CreateEnvelope(keyId: "sha256:unknown");
        var baseline = CreateBaseline(
            signerKeys: ["sha256:known"],
            thresholds: new ThresholdConfig { NewSignerSeverity = AnomalySeverity.Critical });

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "UnknownSigner");
        Assert.Equal(AnomalySeverity.Critical, finding.Severity);
    }

    // ── Unknown OIDC ────────────────────────────────────────────────

    [Fact]
    public void Known_oidc_identity_no_finding()
    {
        var envelope = CreateEnvelope(
            oidcIssuer: "https://token.actions.githubusercontent.com",
            oidcIdentity: "repo:org/repo:ref:refs/heads/main");
        var baseline = CreateBaseline(
            oidcIdentities: new Dictionary<string, List<string>>
            {
                ["https://token.actions.githubusercontent.com"] = ["repo:org/repo:ref:refs/heads/main"]
            });

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownOidcIdentity");
    }

    [Fact]
    public void Unknown_oidc_issuer_produces_critical()
    {
        var envelope = CreateEnvelope(
            oidcIssuer: "https://unknown-issuer.example.com",
            oidcIdentity: "user@example.com");
        var baseline = CreateBaseline();

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "UnknownOidcIdentity");
        Assert.Equal(AnomalySeverity.Critical, finding.Severity);
        Assert.Contains("Unknown OIDC issuer", finding.Message);
    }

    [Fact]
    public void Unknown_identity_under_known_issuer_produces_critical()
    {
        var envelope = CreateEnvelope(
            oidcIssuer: "https://token.actions.githubusercontent.com",
            oidcIdentity: "repo:attacker/evil:ref:refs/heads/main");
        var baseline = CreateBaseline(
            oidcIdentities: new Dictionary<string, List<string>>
            {
                ["https://token.actions.githubusercontent.com"] = ["repo:org/repo:ref:refs/heads/main"]
            });

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "UnknownOidcIdentity");
        Assert.Equal(AnomalySeverity.Critical, finding.Severity);
        Assert.Contains("Unknown OIDC identity", finding.Message);
    }

    [Fact]
    public void No_oidc_in_envelope_no_finding()
    {
        var envelope = CreateEnvelope();
        var baseline = CreateBaseline();

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownOidcIdentity");
    }

    [Fact]
    public void Allowlisted_oidc_identity_suppressed()
    {
        var envelope = CreateEnvelope(
            oidcIssuer: "https://unknown-issuer.example.com",
            oidcIdentity: "trusted-bot@example.com");
        var baseline = CreateBaseline(
            allowlist: new AllowlistConfig { OidcIdentities = ["trusted-bot@example.com"] });

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownOidcIdentity");
    }

    // ── Off-Hours ───────────────────────────────────────────────────

    [Fact]
    public void Signing_within_normal_hours_no_finding()
    {
        var envelope = CreateEnvelope(timestamp: "2026-02-10T14:30:00Z");
        var baseline = CreateBaseline(hours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "OffHoursSigning");
    }

    [Fact]
    public void Signing_outside_normal_hours_produces_warning()
    {
        var envelope = CreateEnvelope(timestamp: "2026-02-10T03:00:00Z");
        var baseline = CreateBaseline(hours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "OffHoursSigning");
        Assert.Equal(AnomalySeverity.Warning, finding.Severity);
        Assert.Contains("hour 3 UTC", finding.Message);
    }

    [Fact]
    public void Empty_signing_hours_in_baseline_all_hours_flagged()
    {
        var envelope = CreateEnvelope(timestamp: "2026-02-10T14:30:00Z");
        var baseline = CreateBaseline(hours: []);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.Contains(report.Findings, f => f.RuleName == "OffHoursSigning");
    }

    [Fact]
    public void Allowlisted_hours_suppressed()
    {
        var envelope = CreateEnvelope(timestamp: "2026-02-10T03:00:00Z");
        var baseline = CreateBaseline(
            hours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
            allowlist: new AllowlistConfig { Hours = [3] });

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "OffHoursSigning");
    }

    // ── Algorithm and Label ─────────────────────────────────────────

    [Fact]
    public void Known_algorithm_no_finding()
    {
        var envelope = CreateEnvelope(algorithm: "ecdsa-p256");
        var baseline = CreateBaseline(algorithms: ["ecdsa-p256"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownAlgorithm");
    }

    [Fact]
    public void Unknown_algorithm_produces_warning()
    {
        var envelope = CreateEnvelope(algorithm: "rsa-pss-sha256");
        var baseline = CreateBaseline(algorithms: ["ecdsa-p256"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "UnknownAlgorithm");
        Assert.Equal(AnomalySeverity.Warning, finding.Severity);
        Assert.Contains("rsa-pss-sha256", finding.Message);
    }

    [Fact]
    public void Known_label_no_finding()
    {
        var envelope = CreateEnvelope(label: "ci-release");
        var baseline = CreateBaseline(labels: ["ci-release", "nightly"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownLabel");
    }

    [Fact]
    public void Unknown_label_produces_info()
    {
        var envelope = CreateEnvelope(label: "rogue-label");
        var baseline = CreateBaseline(labels: ["ci-release", "nightly"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        var finding = Assert.Single(report.Findings, f => f.RuleName == "UnknownLabel");
        Assert.Equal(AnomalySeverity.Info, finding.Severity);
        Assert.Contains("rogue-label", finding.Message);
    }

    [Fact]
    public void Null_label_produces_no_finding()
    {
        var envelope = CreateEnvelope(label: null);
        var baseline = CreateBaseline(labels: ["ci-release"]);

        var report = AnomalyDetector.Detect(envelope, baseline);

        Assert.DoesNotContain(report.Findings, f => f.RuleName == "UnknownLabel");
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private static SignatureEnvelope CreateEnvelope(
        string keyId = "sha256:known",
        string algorithm = "ecdsa-p256",
        string timestamp = "2026-02-10T14:30:00Z",
        string? label = null,
        string? oidcIssuer = null,
        string? oidcIdentity = null)
    {
        return new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test-artifact",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = keyId,
                    Algorithm = algorithm,
                    PublicKey = "dGVzdA==",
                    Value = "c2ln",
                    Timestamp = timestamp,
                    Label = label,
                    OidcIssuer = oidcIssuer,
                    OidcIdentity = oidcIdentity
                }
            ]
        };
    }

    private static BaselineModel CreateBaseline(
        string[]? signerKeys = null,
        string[]? algorithms = null,
        int[]? hours = null,
        string[]? labels = null,
        Dictionary<string, List<string>>? oidcIdentities = null,
        AllowlistConfig? allowlist = null,
        ThresholdConfig? thresholds = null)
    {
        var signers = new Dictionary<string, SignerInfo>();
        foreach (var k in signerKeys ?? ["sha256:known"])
            signers[k] = new SignerInfo { Algorithm = "ecdsa-p256", Count = 1, LastSeen = DateTimeOffset.UtcNow };

        return new BaselineModel
        {
            Signers = signers,
            Algorithms = new List<string>(algorithms ?? ["ecdsa-p256"]),
            SigningHours = new List<int>(hours ?? [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]),
            Labels = new List<string>(labels ?? []),
            OidcIdentities = oidcIdentities ?? new Dictionary<string, List<string>>(),
            Allowlist = allowlist ?? new AllowlistConfig(),
            Thresholds = thresholds ?? new ThresholdConfig()
        };
    }
}
