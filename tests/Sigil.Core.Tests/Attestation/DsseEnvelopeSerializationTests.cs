using System.Text.Json;
using Sigil.Attestation;

namespace Sigil.Core.Tests.Attestation;

public class DsseEnvelopeSerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void Roundtrip_preserves_all_fields()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("test payload"u8),
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = "sha256:abc",
                    Sig = "base64sig",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "base64pk",
                    Timestamp = "2026-02-09T12:00:00Z"
                }
            ]
        };

        var json = JsonSerializer.Serialize(envelope, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<DsseEnvelope>(json, JsonOptions)!;

        Assert.Equal("application/vnd.in-toto+json", deserialized.PayloadType);
        Assert.Equal(envelope.Payload, deserialized.Payload);
        Assert.Single(deserialized.Signatures);
        Assert.Equal("sha256:abc", deserialized.Signatures[0].KeyId);
        Assert.Equal("base64sig", deserialized.Signatures[0].Sig);
        Assert.Equal("ecdsa-p256", deserialized.Signatures[0].Algorithm);
    }

    [Fact]
    public void Default_payloadType_is_intoto()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("x"u8)
        };

        Assert.Equal("application/vnd.in-toto+json", envelope.PayloadType);
    }

    [Fact]
    public void Null_timestampToken_omitted()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("x"u8),
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = "sha256:abc",
                    Sig = "sig",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "pk",
                    Timestamp = "2026-02-09T12:00:00Z"
                }
            ]
        };

        var json = JsonSerializer.Serialize(envelope, JsonOptions);

        Assert.DoesNotContain("timestampToken", json);
    }

    [Fact]
    public void TimestampToken_included_when_present()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("x"u8),
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = "sha256:abc",
                    Sig = "sig",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "pk",
                    Timestamp = "2026-02-09T12:00:00Z",
                    TimestampToken = "base64token"
                }
            ]
        };

        var json = JsonSerializer.Serialize(envelope, JsonOptions);

        Assert.Contains("\"timestampToken\"", json);
    }

    [Fact]
    public void Multiple_signatures_roundtrip()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("multi"u8),
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = "sha256:aaa",
                    Sig = "sig1",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "pk1",
                    Timestamp = "2026-02-09T10:00:00Z"
                },
                new DsseSignature
                {
                    KeyId = "sha256:bbb",
                    Sig = "sig2",
                    Algorithm = "ecdsa-p384",
                    PublicKey = "pk2",
                    Timestamp = "2026-02-09T11:00:00Z"
                }
            ]
        };

        var json = JsonSerializer.Serialize(envelope, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<DsseEnvelope>(json, JsonOptions)!;

        Assert.Equal(2, deserialized.Signatures.Count);
        Assert.Equal("sha256:bbb", deserialized.Signatures[1].KeyId);
    }
}
