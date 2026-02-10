using System.Text.Json;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustedIdentitySerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void RoundTrip_AllFields_Preserved()
    {
        var identity = new TrustedIdentity
        {
            Issuer = "https://token.actions.githubusercontent.com",
            SubjectPattern = "repo:myorg/*",
            DisplayName = "GitHub Actions (myorg)",
            NotAfter = "2026-12-31T23:59:59Z"
        };

        var json = JsonSerializer.Serialize(identity, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<TrustedIdentity>(json, JsonOptions)!;

        Assert.Equal(identity.Issuer, deserialized.Issuer);
        Assert.Equal(identity.SubjectPattern, deserialized.SubjectPattern);
        Assert.Equal(identity.DisplayName, deserialized.DisplayName);
        Assert.Equal(identity.NotAfter, deserialized.NotAfter);
    }

    [Fact]
    public void RoundTrip_NullOptionals_OmittedInJson()
    {
        var identity = new TrustedIdentity
        {
            Issuer = "https://issuer.example.com",
            SubjectPattern = "*"
        };

        var json = JsonSerializer.Serialize(identity, JsonOptions);

        Assert.DoesNotContain("displayName", json);
        Assert.DoesNotContain("notAfter", json);

        var deserialized = JsonSerializer.Deserialize<TrustedIdentity>(json, JsonOptions)!;
        Assert.Null(deserialized.DisplayName);
        Assert.Null(deserialized.NotAfter);
    }

    [Fact]
    public void BundleWithIdentities_RoundTrip()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test-bundle", Created = "2025-01-01T00:00:00Z" },
            Identities =
            [
                new TrustedIdentity
                {
                    Issuer = "https://token.actions.githubusercontent.com",
                    SubjectPattern = "repo:myorg/*",
                    DisplayName = "GitHub CI"
                },
                new TrustedIdentity
                {
                    Issuer = "https://accounts.google.com",
                    SubjectPattern = "*@example.com"
                }
            ]
        };

        var json = JsonSerializer.Serialize(bundle, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<TrustBundle>(json, JsonOptions)!;

        Assert.Equal(2, deserialized.Identities.Count);
        Assert.Equal("https://token.actions.githubusercontent.com", deserialized.Identities[0].Issuer);
        Assert.Equal("repo:myorg/*", deserialized.Identities[0].SubjectPattern);
    }

    [Fact]
    public void BundleWithEmptyIdentities_RoundTrip()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test-bundle", Created = "2025-01-01T00:00:00Z" }
        };

        var json = JsonSerializer.Serialize(bundle, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<TrustBundle>(json, JsonOptions)!;

        Assert.Empty(deserialized.Identities);
    }
}
