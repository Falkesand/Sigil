using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class BundleSignature
{
    [JsonPropertyName("keyId")]
    public required string KeyId { get; set; }

    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; set; }

    [JsonPropertyName("publicKey")]
    public required string PublicKey { get; set; }

    [JsonPropertyName("value")]
    public required string Value { get; set; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; set; }
}
