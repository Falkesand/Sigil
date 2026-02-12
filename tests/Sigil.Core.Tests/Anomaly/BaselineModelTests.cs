using Sigil.Anomaly;

namespace Sigil.Core.Tests.Anomaly;

public class BaselineModelTests
{
    [Fact]
    public void Default_model_has_empty_collections()
    {
        var model = new BaselineModel();

        Assert.Equal("1.0", model.Version);
        Assert.Equal("anomaly-baseline", model.Kind);
        Assert.Empty(model.Signers);
        Assert.Empty(model.OidcIdentities);
        Assert.Empty(model.SigningHours);
        Assert.Empty(model.Algorithms);
        Assert.Empty(model.Labels);
    }

    [Fact]
    public void Model_with_signers_preserves_data()
    {
        var now = DateTimeOffset.UtcNow;
        var model = new BaselineModel
        {
            Signers = new Dictionary<string, SignerInfo>
            {
                ["abc123"] = new SignerInfo
                {
                    Count = 5,
                    Algorithm = "ecdsa-p256",
                    LastSeen = now
                }
            },
            SampleCount = 5
        };

        Assert.Single(model.Signers);
        Assert.Equal(5, model.Signers["abc123"].Count);
        Assert.Equal("ecdsa-p256", model.Signers["abc123"].Algorithm);
        Assert.Equal(now, model.Signers["abc123"].LastSeen);
        Assert.Equal(5, model.SampleCount);
    }

    [Fact]
    public void Thresholds_have_sensible_defaults()
    {
        var thresholds = new ThresholdConfig();

        Assert.Equal(AnomalySeverity.Warning, thresholds.NewSignerSeverity);
        Assert.Equal(AnomalySeverity.Warning, thresholds.OffHoursSeverity);
        Assert.Equal(AnomalySeverity.Critical, thresholds.UnknownOidcSeverity);
        Assert.Equal(AnomalySeverity.Warning, thresholds.UnknownAlgorithmSeverity);
        Assert.Equal(AnomalySeverity.Info, thresholds.UnknownLabelSeverity);
    }

    [Fact]
    public void Allowlist_sections_are_empty_by_default()
    {
        var allowlist = new AllowlistConfig();

        Assert.Empty(allowlist.Signers);
        Assert.Empty(allowlist.OidcIdentities);
        Assert.Empty(allowlist.Hours);
        Assert.Empty(allowlist.Labels);
    }
}
