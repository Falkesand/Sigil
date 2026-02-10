using System.Text.Json;
using Sigil.Signing;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Signing;

public class TransparencyFieldsSerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void WithTransparencyFields_roundtrips()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-08T12:00:00Z",
            TransparencyLogUrl = "https://log.example.com",
            TransparencyLogIndex = 42,
            TransparencySignedCheckpoint = "dGVzdA==",
            TransparencyInclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 42,
                TreeSize = 100,
                RootHash = "aabbccdd",
                Hashes = ["1111", "2222"]
            }
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<SignatureEntry>(json, JsonOptions)!;

        Assert.Equal("https://log.example.com", deserialized.TransparencyLogUrl);
        Assert.Equal(42, deserialized.TransparencyLogIndex);
        Assert.Equal("dGVzdA==", deserialized.TransparencySignedCheckpoint);
        Assert.NotNull(deserialized.TransparencyInclusionProof);
        Assert.Equal(42, deserialized.TransparencyInclusionProof.LeafIndex);
        Assert.Equal(100, deserialized.TransparencyInclusionProof.TreeSize);
        Assert.Equal("aabbccdd", deserialized.TransparencyInclusionProof.RootHash);
        Assert.Equal(2, deserialized.TransparencyInclusionProof.Hashes.Count);
    }

    [Fact]
    public void WithoutTransparencyFields_deserializes()
    {
        var json = """
        {
            "keyId": "sha256:abc123",
            "algorithm": "ecdsa-p256",
            "publicKey": "AQID",
            "value": "BAUG",
            "timestamp": "2026-02-08T12:00:00Z"
        }
        """;

        var entry = JsonSerializer.Deserialize<SignatureEntry>(json, JsonOptions)!;

        Assert.Null(entry.TransparencyLogUrl);
        Assert.Null(entry.TransparencyLogIndex);
        Assert.Null(entry.TransparencySignedCheckpoint);
        Assert.Null(entry.TransparencyInclusionProof);
    }

    [Fact]
    public void Null_transparency_fields_omitted_from_json()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-08T12:00:00Z"
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);

        Assert.DoesNotContain("transparencyLogUrl", json);
        Assert.DoesNotContain("transparencyLogIndex", json);
        Assert.DoesNotContain("transparencySignedCheckpoint", json);
        Assert.DoesNotContain("transparencyInclusionProof", json);
    }

    [Fact]
    public void Envelope_roundtrip_with_transparency()
    {
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.txt",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:abc",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "AQID",
                    Value = "BAUG",
                    Timestamp = "2026-02-08T12:00:00Z",
                    TransparencyLogUrl = "https://log.example.com",
                    TransparencyLogIndex = 7,
                    TransparencySignedCheckpoint = "Y2hlY2twb2ludA==",
                    TransparencyInclusionProof = new RemoteInclusionProof
                    {
                        LeafIndex = 7,
                        TreeSize = 16,
                        RootHash = "deadbeef",
                        Hashes = ["aabb"]
                    }
                }
            ]
        };

        var json = ArtifactSigner.Serialize(envelope);
        var restored = ArtifactSigner.Deserialize(json);

        Assert.Single(restored.Signatures);
        var sig = restored.Signatures[0];
        Assert.Equal("https://log.example.com", sig.TransparencyLogUrl);
        Assert.Equal(7, sig.TransparencyLogIndex);
        Assert.Equal("Y2hlY2twb2ludA==", sig.TransparencySignedCheckpoint);
        Assert.NotNull(sig.TransparencyInclusionProof);
        Assert.Equal(7, sig.TransparencyInclusionProof.LeafIndex);
    }

    [Fact]
    public void Backward_compat_existing_envelope_without_transparency_fields()
    {
        var json = """
        {
            "version": "1.0",
            "subject": {
                "digests": { "sha256": "abc" },
                "name": "test.txt"
            },
            "signatures": [
                {
                    "keyId": "sha256:abc",
                    "algorithm": "ecdsa-p256",
                    "publicKey": "AQID",
                    "value": "BAUG",
                    "timestamp": "2026-02-08T12:00:00Z"
                }
            ]
        }
        """;

        var envelope = ArtifactSigner.Deserialize(json);

        Assert.Single(envelope.Signatures);
        var sig = envelope.Signatures[0];
        Assert.Null(sig.TransparencyLogUrl);
        Assert.Null(sig.TransparencyLogIndex);
        Assert.Null(sig.TransparencySignedCheckpoint);
        Assert.Null(sig.TransparencyInclusionProof);
    }

    [Fact]
    public void Transparency_and_oidc_fields_coexist()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-08T12:00:00Z",
            OidcToken = "jwt.token.here",
            OidcIssuer = "https://accounts.google.com",
            OidcIdentity = "user@example.com",
            TransparencyLogUrl = "https://log.example.com",
            TransparencyLogIndex = 5
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<SignatureEntry>(json, JsonOptions)!;

        Assert.Equal("jwt.token.here", deserialized.OidcToken);
        Assert.Equal("https://log.example.com", deserialized.TransparencyLogUrl);
        Assert.Equal(5, deserialized.TransparencyLogIndex);
    }

    [Fact]
    public void Transparency_and_timestamp_fields_coexist()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-08T12:00:00Z",
            TimestampToken = "dGVzdHRva2Vu",
            TransparencyLogUrl = "https://log.example.com",
            TransparencyLogIndex = 99
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<SignatureEntry>(json, JsonOptions)!;

        Assert.Equal("dGVzdHRva2Vu", deserialized.TimestampToken);
        Assert.Equal("https://log.example.com", deserialized.TransparencyLogUrl);
        Assert.Equal(99, deserialized.TransparencyLogIndex);
    }
}
