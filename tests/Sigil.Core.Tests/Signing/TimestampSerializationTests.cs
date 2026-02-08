using System.Text.Json;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class TimestampSerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void WithTimestampToken_roundtrips()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-08T12:00:00Z",
            Label = "test",
            TimestampToken = "dGVzdHRva2Vu"
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<SignatureEntry>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("dGVzdHRva2Vu", deserialized.TimestampToken);
        Assert.Equal(entry.KeyId, deserialized.KeyId);
        Assert.Equal(entry.Algorithm, deserialized.Algorithm);
    }

    [Fact]
    public void WithoutTimestampToken_deserializes()
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

        var entry = JsonSerializer.Deserialize<SignatureEntry>(json, JsonOptions);

        Assert.NotNull(entry);
        Assert.Null(entry.TimestampToken);
    }

    [Fact]
    public void Null_omitted_from_json()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-08T12:00:00Z",
            TimestampToken = null
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);

        Assert.DoesNotContain("timestampToken", json);
    }

    [Fact]
    public void Envelope_roundtrip_with_timestamp()
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
                    TimestampToken = "dGVzdA=="
                }
            ]
        };

        var json = ArtifactSigner.Serialize(envelope);
        var restored = ArtifactSigner.Deserialize(json);

        Assert.Single(restored.Signatures);
        Assert.Equal("dGVzdA==", restored.Signatures[0].TimestampToken);
    }
}
