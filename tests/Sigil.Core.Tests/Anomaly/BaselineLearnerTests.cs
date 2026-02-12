using Sigil.Anomaly;
using Sigil.Signing;

namespace Sigil.Core.Tests.Anomaly;

public class BaselineLearnerTests
{
    [Fact]
    public void Learn_from_empty_list_returns_empty_baseline()
    {
        var result = BaselineLearner.Learn([]);

        Assert.True(result.IsSuccess);
        var model = result.Value;
        Assert.Equal(0, model.SampleCount);
        Assert.Empty(model.Signers);
        Assert.Empty(model.OidcIdentities);
        Assert.Empty(model.SigningHours);
        Assert.Empty(model.Algorithms);
        Assert.Empty(model.Labels);
        Assert.Equal("1.0", model.Version);
        Assert.Equal("anomaly-baseline", model.Kind);
    }

    [Fact]
    public void Learn_from_single_envelope_extracts_signer()
    {
        var envelope = CreateEnvelope(keyId: "sha256:key1", algorithm: "ecdsa-p384");

        var result = BaselineLearner.Learn([envelope]);

        Assert.True(result.IsSuccess);
        var model = result.Value;
        Assert.Equal(1, model.SampleCount);
        Assert.Single(model.Signers);
        Assert.True(model.Signers.ContainsKey("sha256:key1"));
        Assert.Equal(1, model.Signers["sha256:key1"].Count);
        Assert.Equal("ecdsa-p384", model.Signers["sha256:key1"].Algorithm);
    }

    [Fact]
    public void Learn_from_multiple_envelopes_aggregates_signers()
    {
        var envelope1 = CreateEnvelope(keyId: "sha256:key1", timestamp: "2026-02-10T10:00:00Z");
        var envelope2 = CreateEnvelope(keyId: "sha256:key1", timestamp: "2026-02-10T12:00:00Z");

        var result = BaselineLearner.Learn([envelope1, envelope2]);

        Assert.True(result.IsSuccess);
        var model = result.Value;
        Assert.Equal(2, model.SampleCount);
        Assert.Single(model.Signers);
        Assert.Equal(2, model.Signers["sha256:key1"].Count);
    }

    [Fact]
    public void Learn_extracts_oidc_identities()
    {
        var envelope = CreateEnvelope(
            oidcIssuer: "https://token.actions.githubusercontent.com",
            oidcIdentity: "repo:org/repo:ref:refs/heads/main");

        var result = BaselineLearner.Learn([envelope]);

        Assert.True(result.IsSuccess);
        var model = result.Value;
        Assert.Single(model.OidcIdentities);
        Assert.True(model.OidcIdentities.ContainsKey("https://token.actions.githubusercontent.com"));
        Assert.Equal(
            ["repo:org/repo:ref:refs/heads/main"],
            model.OidcIdentities["https://token.actions.githubusercontent.com"]);
    }

    [Fact]
    public void Learn_extracts_signing_hours()
    {
        var envelope1 = CreateEnvelope(timestamp: "2026-02-10T08:30:00Z");
        var envelope2 = CreateEnvelope(timestamp: "2026-02-10T16:45:00Z");

        var result = BaselineLearner.Learn([envelope1, envelope2]);

        Assert.True(result.IsSuccess);
        var model = result.Value;
        Assert.Equal(2, model.SigningHours.Count);
        Assert.Contains(8, model.SigningHours);
        Assert.Contains(16, model.SigningHours);
    }

    [Fact]
    public void Learn_extracts_algorithms_and_labels()
    {
        var envelope1 = CreateEnvelope(algorithm: "ecdsa-p256", label: "ci-release");
        var envelope2 = CreateEnvelope(algorithm: "ecdsa-p384", label: "nightly");
        var envelope3 = CreateEnvelope(algorithm: "ecdsa-p256", label: null);

        var result = BaselineLearner.Learn([envelope1, envelope2, envelope3]);

        Assert.True(result.IsSuccess);
        var model = result.Value;
        Assert.Equal(2, model.Algorithms.Count);
        Assert.Contains("ecdsa-p256", model.Algorithms);
        Assert.Contains("ecdsa-p384", model.Algorithms);
        Assert.Equal(2, model.Labels.Count);
        Assert.Contains("ci-release", model.Labels);
        Assert.Contains("nightly", model.Labels);
    }

    private static SignatureEnvelope CreateEnvelope(
        string keyId = "sha256:abc123",
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
                Digests = new Dictionary<string, string> { ["sha256"] = "abc123" }
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
}
