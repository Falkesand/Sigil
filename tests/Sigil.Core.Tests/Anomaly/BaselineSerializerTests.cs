using System.Text.Json;
using Sigil.Anomaly;

namespace Sigil.Core.Tests.Anomaly;

public class BaselineSerializerTests
{
    [Fact]
    public void Serialize_roundtrip_preserves_all_fields()
    {
        var now = DateTimeOffset.UtcNow;
        var model = new BaselineModel
        {
            Version = "1.0",
            Kind = "anomaly-baseline",
            CreatedAt = now,
            UpdatedAt = now,
            SampleCount = 42,
            Signers = new Dictionary<string, SignerInfo>
            {
                ["sha256:abc123"] = new SignerInfo
                {
                    Count = 30,
                    Algorithm = "ecdsa-p256",
                    LastSeen = now
                }
            },
            OidcIdentities = new Dictionary<string, List<string>>
            {
                ["https://token.actions.githubusercontent.com"] = ["repo:org/repo:ref:refs/heads/main"]
            },
            SigningHours = [8, 9, 10, 14, 15],
            Algorithms = ["ecdsa-p256", "ecdsa-p384"],
            Labels = ["ci-release", "nightly"],
            Allowlist = new AllowlistConfig
            {
                Signers = ["sha256:trusted"],
                OidcIdentities = ["https://accounts.google.com"],
                Hours = [3, 4],
                Labels = ["emergency"]
            },
            Thresholds = new ThresholdConfig
            {
                NewSignerSeverity = AnomalySeverity.Critical,
                OffHoursSeverity = AnomalySeverity.Info,
                UnknownOidcSeverity = AnomalySeverity.Warning,
                UnknownAlgorithmSeverity = AnomalySeverity.Critical,
                UnknownLabelSeverity = AnomalySeverity.Warning
            }
        };

        var json = BaselineSerializer.Serialize(model);
        var result = BaselineSerializer.Deserialize(json);

        Assert.True(result.IsSuccess);
        var deserialized = result.Value;

        Assert.Equal(model.Version, deserialized.Version);
        Assert.Equal(model.Kind, deserialized.Kind);
        Assert.Equal(model.CreatedAt, deserialized.CreatedAt);
        Assert.Equal(model.UpdatedAt, deserialized.UpdatedAt);
        Assert.Equal(model.SampleCount, deserialized.SampleCount);

        Assert.Single(deserialized.Signers);
        Assert.Equal(30, deserialized.Signers["sha256:abc123"].Count);
        Assert.Equal("ecdsa-p256", deserialized.Signers["sha256:abc123"].Algorithm);
        Assert.Equal(now, deserialized.Signers["sha256:abc123"].LastSeen);

        Assert.Single(deserialized.OidcIdentities);
        Assert.Equal(
            ["repo:org/repo:ref:refs/heads/main"],
            deserialized.OidcIdentities["https://token.actions.githubusercontent.com"]);

        Assert.Equal([8, 9, 10, 14, 15], deserialized.SigningHours);
        Assert.Equal(["ecdsa-p256", "ecdsa-p384"], deserialized.Algorithms);
        Assert.Equal(["ci-release", "nightly"], deserialized.Labels);

        Assert.Equal(["sha256:trusted"], deserialized.Allowlist.Signers);
        Assert.Equal(["https://accounts.google.com"], deserialized.Allowlist.OidcIdentities);
        Assert.Equal([3, 4], deserialized.Allowlist.Hours);
        Assert.Equal(["emergency"], deserialized.Allowlist.Labels);

        Assert.Equal(AnomalySeverity.Critical, deserialized.Thresholds.NewSignerSeverity);
        Assert.Equal(AnomalySeverity.Info, deserialized.Thresholds.OffHoursSeverity);
        Assert.Equal(AnomalySeverity.Warning, deserialized.Thresholds.UnknownOidcSeverity);
        Assert.Equal(AnomalySeverity.Critical, deserialized.Thresholds.UnknownAlgorithmSeverity);
        Assert.Equal(AnomalySeverity.Warning, deserialized.Thresholds.UnknownLabelSeverity);
    }

    [Fact]
    public void Serialize_includes_version_and_kind()
    {
        var model = new BaselineModel();

        var json = BaselineSerializer.Serialize(model);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("1.0", root.GetProperty("version").GetString());
        Assert.Equal("anomaly-baseline", root.GetProperty("kind").GetString());
    }

    [Fact]
    public void Deserialize_invalid_json_returns_error()
    {
        var result = BaselineSerializer.Deserialize("{invalid");

        Assert.False(result.IsSuccess);
        Assert.Equal(AnomalyErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Deserialize_unsupported_version_returns_error()
    {
        var json = """
            {
                "version": "2.0",
                "kind": "anomaly-baseline",
                "createdAt": "2026-01-01T00:00:00+00:00",
                "updatedAt": "2026-01-01T00:00:00+00:00",
                "sampleCount": 0,
                "signers": {},
                "oidcIdentities": {},
                "signingHours": [],
                "algorithms": [],
                "labels": [],
                "allowlist": { "signers": [], "oidcIdentities": [], "hours": [], "labels": [] },
                "thresholds": {}
            }
            """;

        var result = BaselineSerializer.Deserialize(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(AnomalyErrorKind.BaselineCorrupt, result.ErrorKind);
        Assert.Contains("Unsupported baseline version: 2.0", result.ErrorMessage);
    }

    [Fact]
    public void Deserialize_null_throws_ArgumentException()
    {
        Assert.ThrowsAny<ArgumentException>(() => BaselineSerializer.Deserialize(null!));
    }

    [Fact]
    public void Deserialize_empty_object_returns_error()
    {
        var result = BaselineSerializer.Deserialize("{}");

        Assert.False(result.IsSuccess);
        Assert.Equal(AnomalyErrorKind.BaselineCorrupt, result.ErrorKind);
        Assert.Contains("version", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
