using System.Text.Json;
using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class ImpactAnalyzerFormatTests
{
    private static ImpactReport CreateFullReport() => new()
    {
        KeyId = "key:sha256:abc123",
        Fingerprint = "sha256:abc123",
        KeyLabel = "production-signing",
        IsRevoked = true,
        RevokedAt = "2026-01-15T00:00:00Z",
        RevocationReason = "key leaked",
        DirectArtifacts = ["artifact:lib.dll", "artifact:app.dll"],
        TransitiveArtifacts = ["artifact:downstream.dll"],
        EndorsedKeys = ["key:sha256:child1"],
        EndorsedByKeys = ["key:sha256:root"],
        BoundIdentities = ["identity:github.com/myorg"],
        Recommendations = ["Rotate to a new key pair", "Audit transparency logs for unauthorized signatures"],
    };

    private static ImpactReport CreateMinimalReport() => new()
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
        Recommendations = ["Rotate to a new key pair"],
    };

    // --- Text format tests ---

    [Fact]
    public void FormatText_includes_header()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Key Compromise Impact Report", text);
        Assert.Contains("=============================", text);
    }

    [Fact]
    public void FormatText_includes_key_details()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Key:          sha256:abc123", text);
        Assert.Contains("Label:        production-signing", text);
    }

    [Fact]
    public void FormatText_revoked_key_shows_status()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("REVOKED", text);
        Assert.Contains("2026-01-15T00:00:00Z", text);
        Assert.Contains("key leaked", text);
    }

    [Fact]
    public void FormatText_active_key_shows_not_revoked()
    {
        var text = ImpactAnalyzer.FormatText(CreateMinimalReport());

        Assert.Contains("ACTIVE (not yet revoked)", text);
    }

    [Fact]
    public void FormatText_includes_direct_artifacts()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Direct Impact: 2 artifacts", text);
        Assert.Contains("artifact:lib.dll", text);
        Assert.Contains("artifact:app.dll", text);
    }

    [Fact]
    public void FormatText_includes_transitive_artifacts()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Transitive Impact: 1 artifact (via endorsement chain)", text);
        Assert.Contains("artifact:downstream.dll", text);
    }

    [Fact]
    public void FormatText_includes_endorsement_chain()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Endorsement Chain:", text);
        Assert.Contains("Endorses: 1 key", text);
        Assert.Contains("key:sha256:child1", text);
        Assert.Contains("Endorsed by: 1 key", text);
        Assert.Contains("key:sha256:root", text);
    }

    [Fact]
    public void FormatText_includes_bound_identities()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Bound Identities: 1", text);
        Assert.Contains("identity:github.com/myorg", text);
    }

    [Fact]
    public void FormatText_includes_recommendations()
    {
        var text = ImpactAnalyzer.FormatText(CreateFullReport());

        Assert.Contains("Recommendations:", text);
        Assert.Contains("1. Rotate to a new key pair", text);
        Assert.Contains("2. Audit transparency logs for unauthorized signatures", text);
    }

    [Fact]
    public void FormatText_minimal_report_omits_empty_sections()
    {
        var text = ImpactAnalyzer.FormatText(CreateMinimalReport());

        Assert.DoesNotContain("Transitive Impact:", text);
        Assert.DoesNotContain("Endorsement Chain:", text);
        Assert.DoesNotContain("Bound Identities:", text);
    }

    [Fact]
    public void FormatText_omits_label_when_null()
    {
        var text = ImpactAnalyzer.FormatText(CreateMinimalReport());

        Assert.DoesNotContain("Label:", text);
    }

    // --- JSON format tests ---

    [Fact]
    public void FormatJson_valid_json()
    {
        var json = ImpactAnalyzer.FormatJson(CreateFullReport());

        var doc = JsonDocument.Parse(json);
        Assert.NotNull(doc);
    }

    [Fact]
    public void FormatJson_contains_all_fields()
    {
        var json = ImpactAnalyzer.FormatJson(CreateFullReport());

        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("key:sha256:abc123", root.GetProperty("keyId").GetString());
        Assert.Equal("sha256:abc123", root.GetProperty("fingerprint").GetString());
        Assert.Equal("production-signing", root.GetProperty("keyLabel").GetString());
        Assert.True(root.GetProperty("isRevoked").GetBoolean());
        Assert.Equal("2026-01-15T00:00:00Z", root.GetProperty("revokedAt").GetString());
        Assert.Equal("key leaked", root.GetProperty("revocationReason").GetString());
        Assert.Equal(2, root.GetProperty("directArtifacts").GetArrayLength());
        Assert.Equal(1, root.GetProperty("transitiveArtifacts").GetArrayLength());
        Assert.Equal(1, root.GetProperty("endorsedKeys").GetArrayLength());
        Assert.Equal(1, root.GetProperty("endorsedByKeys").GetArrayLength());
        Assert.Equal(1, root.GetProperty("boundIdentities").GetArrayLength());
        Assert.Equal(2, root.GetProperty("recommendations").GetArrayLength());
    }

    [Fact]
    public void FormatJson_null_fields_omitted()
    {
        var json = ImpactAnalyzer.FormatJson(CreateMinimalReport());

        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.False(root.TryGetProperty("keyLabel", out _));
        Assert.False(root.TryGetProperty("revokedAt", out _));
        Assert.False(root.TryGetProperty("revocationReason", out _));
    }

    [Fact]
    public void FormatJson_empty_arrays_present()
    {
        var json = ImpactAnalyzer.FormatJson(CreateMinimalReport());

        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal(0, root.GetProperty("directArtifacts").GetArrayLength());
        Assert.Equal(0, root.GetProperty("transitiveArtifacts").GetArrayLength());
        Assert.Equal(0, root.GetProperty("endorsedKeys").GetArrayLength());
    }
}
