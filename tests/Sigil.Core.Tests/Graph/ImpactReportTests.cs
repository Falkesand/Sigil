using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class ImpactReportTests
{
    [Fact]
    public void Report_exposes_all_properties()
    {
        var report = new ImpactReport
        {
            KeyId = "key:sha256:abc123",
            Fingerprint = "sha256:abc123",
            KeyLabel = "production-signing",
            IsRevoked = true,
            RevokedAt = "2026-01-15T00:00:00Z",
            RevocationReason = "key leaked",
            DirectArtifacts = ["artifact:lib.dll"],
            TransitiveArtifacts = ["artifact:downstream.dll"],
            EndorsedKeys = ["key:sha256:child1"],
            EndorsedByKeys = ["key:sha256:root"],
            BoundIdentities = ["identity:github.com/myorg"],
            Recommendations = ["Rotate to a new key pair"],
        };

        Assert.Equal("key:sha256:abc123", report.KeyId);
        Assert.Equal("sha256:abc123", report.Fingerprint);
        Assert.Equal("production-signing", report.KeyLabel);
        Assert.True(report.IsRevoked);
        Assert.Equal("2026-01-15T00:00:00Z", report.RevokedAt);
        Assert.Equal("key leaked", report.RevocationReason);
        Assert.Single(report.DirectArtifacts);
        Assert.Single(report.TransitiveArtifacts);
        Assert.Single(report.EndorsedKeys);
        Assert.Single(report.EndorsedByKeys);
        Assert.Single(report.BoundIdentities);
        Assert.Single(report.Recommendations);
    }

    [Fact]
    public void Report_allows_null_optional_fields()
    {
        var report = new ImpactReport
        {
            KeyId = "key:sha256:abc123",
            Fingerprint = "sha256:abc123",
            KeyLabel = null,
            IsRevoked = false,
            RevokedAt = null,
            RevocationReason = null,
            DirectArtifacts = [],
            TransitiveArtifacts = [],
            EndorsedKeys = [],
            EndorsedByKeys = [],
            BoundIdentities = [],
            Recommendations = [],
        };

        Assert.Null(report.KeyLabel);
        Assert.Null(report.RevokedAt);
        Assert.Null(report.RevocationReason);
    }

    [Fact]
    public void Report_direct_artifacts_is_readonly()
    {
        var report = new ImpactReport
        {
            KeyId = "key:sha256:abc123",
            Fingerprint = "sha256:abc123",
            KeyLabel = null,
            IsRevoked = false,
            RevokedAt = null,
            RevocationReason = null,
            DirectArtifacts = ["artifact:a.dll", "artifact:b.dll"],
            TransitiveArtifacts = [],
            EndorsedKeys = [],
            EndorsedByKeys = [],
            BoundIdentities = [],
            Recommendations = [],
        };

        Assert.Equal(2, report.DirectArtifacts.Count);
    }

    [Fact]
    public void Report_multiple_recommendations()
    {
        var report = new ImpactReport
        {
            KeyId = "key:sha256:abc123",
            Fingerprint = "sha256:abc123",
            KeyLabel = null,
            IsRevoked = false,
            RevokedAt = null,
            RevocationReason = null,
            DirectArtifacts = [],
            TransitiveArtifacts = [],
            EndorsedKeys = [],
            EndorsedByKeys = [],
            BoundIdentities = [],
            Recommendations = ["Step 1", "Step 2", "Step 3"],
        };

        Assert.Equal(3, report.Recommendations.Count);
        Assert.Equal("Step 1", report.Recommendations[0]);
        Assert.Equal("Step 2", report.Recommendations[1]);
        Assert.Equal("Step 3", report.Recommendations[2]);
    }

    [Fact]
    public void Report_empty_collections_are_valid()
    {
        var report = new ImpactReport
        {
            KeyId = "key:sha256:empty",
            Fingerprint = "sha256:empty",
            KeyLabel = null,
            IsRevoked = false,
            RevokedAt = null,
            RevocationReason = null,
            DirectArtifacts = [],
            TransitiveArtifacts = [],
            EndorsedKeys = [],
            EndorsedByKeys = [],
            BoundIdentities = [],
            Recommendations = [],
        };

        Assert.Empty(report.DirectArtifacts);
        Assert.Empty(report.TransitiveArtifacts);
        Assert.Empty(report.EndorsedKeys);
        Assert.Empty(report.EndorsedByKeys);
        Assert.Empty(report.BoundIdentities);
        Assert.Empty(report.Recommendations);
    }
}
