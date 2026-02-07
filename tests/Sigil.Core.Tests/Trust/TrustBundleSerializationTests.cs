using System.Text.Json;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustBundleSerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void Round_trip_full_bundle()
    {
        var bundle = CreateFullBundle();

        var json = JsonSerializer.Serialize(bundle, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<TrustBundle>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("1.0", deserialized.Version);
        Assert.Equal("trust-bundle", deserialized.Kind);
        Assert.Equal("test-bundle", deserialized.Metadata.Name);
        Assert.Equal("Test bundle", deserialized.Metadata.Description);
        Assert.NotNull(deserialized.Metadata.Created);
        Assert.Single(deserialized.Keys);
        Assert.Equal("sha256:abc123", deserialized.Keys[0].Fingerprint);
        Assert.Equal("Test Key", deserialized.Keys[0].DisplayName);
        Assert.NotNull(deserialized.Keys[0].Scopes);
        Assert.Equal(["*.tar.gz"], deserialized.Keys[0].Scopes!.NamePatterns);
        Assert.Equal(["release"], deserialized.Keys[0].Scopes!.Labels);
        Assert.Equal(["ecdsa-p256"], deserialized.Keys[0].Scopes!.Algorithms);
        Assert.NotNull(deserialized.Keys[0].NotAfter);
        Assert.Single(deserialized.Endorsements);
        Assert.Equal("sha256:aaa", deserialized.Endorsements[0].Endorser);
        Assert.Equal("sha256:bbb", deserialized.Endorsements[0].Endorsed);
    }

    [Fact]
    public void Round_trip_minimal_bundle_no_optional_fields()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "minimal",
                Created = "2026-02-08T12:00:00Z"
            }
        };

        var json = JsonSerializer.Serialize(bundle, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<TrustBundle>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("1.0", deserialized.Version);
        Assert.Equal("trust-bundle", deserialized.Kind);
        Assert.Equal("minimal", deserialized.Metadata.Name);
        Assert.Null(deserialized.Metadata.Description);
        Assert.Empty(deserialized.Keys);
        Assert.Empty(deserialized.Endorsements);
        Assert.Null(deserialized.Signature);
    }

    [Fact]
    public void Key_entry_with_null_scopes_round_trips()
    {
        var entry = new TrustedKeyEntry
        {
            Fingerprint = "sha256:abc123",
            DisplayName = "No scopes"
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<TrustedKeyEntry>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Null(deserialized.Scopes);
        Assert.Null(deserialized.NotAfter);
    }

    [Fact]
    public void Endorsement_round_trip()
    {
        var endorsement = new Endorsement
        {
            Endorser = "sha256:aaa",
            Endorsed = "sha256:bbb",
            Statement = "Trusted CI key",
            Timestamp = "2026-02-08T12:00:00Z"
        };

        var json = JsonSerializer.Serialize(endorsement, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<Endorsement>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("sha256:aaa", deserialized.Endorser);
        Assert.Equal("sha256:bbb", deserialized.Endorsed);
        Assert.Equal("Trusted CI key", deserialized.Statement);
        Assert.Null(deserialized.Scopes);
        Assert.Null(deserialized.NotAfter);
    }

    [Fact]
    public void Bundle_signature_round_trip()
    {
        var sig = new BundleSignature
        {
            KeyId = "sha256:def456",
            Algorithm = "ecdsa-p256",
            PublicKey = "base64SPKI",
            Value = "base64sig",
            Timestamp = "2026-02-08T12:00:00Z"
        };

        var json = JsonSerializer.Serialize(sig, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<BundleSignature>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("sha256:def456", deserialized.KeyId);
        Assert.Equal("ecdsa-p256", deserialized.Algorithm);
        Assert.Equal("base64SPKI", deserialized.PublicKey);
        Assert.Equal("base64sig", deserialized.Value);
    }

    [Fact]
    public void Json_property_names_use_camelCase()
    {
        var bundle = CreateFullBundle();
        var json = JsonSerializer.Serialize(bundle, JsonOptions);

        Assert.Contains("\"version\"", json);
        Assert.Contains("\"kind\"", json);
        Assert.Contains("\"metadata\"", json);
        Assert.Contains("\"keys\"", json);
        Assert.Contains("\"endorsements\"", json);
        Assert.Contains("\"fingerprint\"", json);
        Assert.Contains("\"displayName\"", json);
        Assert.Contains("\"namePatterns\"", json);
        Assert.Contains("\"notAfter\"", json);
        Assert.Contains("\"endorser\"", json);
        Assert.Contains("\"endorsed\"", json);
        Assert.Contains("\"statement\"", json);
    }

    [Fact]
    public void TrustDecision_has_expected_values()
    {
        Assert.Equal(0, (int)TrustDecision.Trusted);
        Assert.Equal(1, (int)TrustDecision.TrustedViaEndorsement);
        Assert.Equal(2, (int)TrustDecision.Untrusted);
        Assert.Equal(3, (int)TrustDecision.Expired);
        Assert.Equal(4, (int)TrustDecision.ScopeMismatch);
        Assert.Equal(5, (int)TrustDecision.BundleInvalid);
    }

    private static TrustBundle CreateFullBundle() => new()
    {
        Metadata = new BundleMetadata
        {
            Name = "test-bundle",
            Description = "Test bundle",
            Created = "2026-02-08T12:00:00Z"
        },
        Keys =
        [
            new TrustedKeyEntry
            {
                Fingerprint = "sha256:abc123",
                DisplayName = "Test Key",
                Scopes = new TrustScopes
                {
                    NamePatterns = ["*.tar.gz"],
                    Labels = ["release"],
                    Algorithms = ["ecdsa-p256"]
                },
                NotAfter = "2027-02-08T00:00:00Z"
            }
        ],
        Endorsements =
        [
            new Endorsement
            {
                Endorser = "sha256:aaa",
                Endorsed = "sha256:bbb",
                Statement = "Authorized build key",
                Scopes = new TrustScopes
                {
                    NamePatterns = ["*.tar.gz"],
                    Labels = ["ci-pipeline"]
                },
                NotAfter = "2027-01-01T00:00:00Z",
                Timestamp = "2026-02-08T12:00:00Z"
            }
        ]
    };
}
