using System.Text.Json.Serialization;

namespace Secure.Sbom.Keys;

public sealed class KeyMetadata
{
    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("label")]
    public string? Label { get; set; }

    [JsonPropertyName("createdAt")]
    public required DateTimeOffset CreatedAt { get; init; }

    [JsonPropertyName("fingerprint")]
    public required string Fingerprint { get; init; }

    [JsonPropertyName("hasPrivateKey")]
    public bool HasPrivateKey { get; init; }
}
