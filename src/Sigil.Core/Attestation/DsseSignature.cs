using System.Text.Json.Serialization;

namespace Sigil.Attestation;

public sealed class DsseSignature
{
    [JsonPropertyName("keyid")]
    public required string KeyId { get; init; }

    [JsonPropertyName("sig")]
    public required string Sig { get; init; }

    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("publicKey")]
    public required string PublicKey { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }

    [JsonPropertyName("timestampToken")]
    public string? TimestampToken { get; init; }
}
