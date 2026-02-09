using System.Text.Json.Serialization;

namespace Sigil.Transparency;

public sealed class LogEntry
{
    [JsonPropertyName("index")]
    public required long Index { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }

    [JsonPropertyName("keyId")]
    public required string KeyId { get; init; }

    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("artifactName")]
    public required string ArtifactName { get; init; }

    [JsonPropertyName("artifactDigest")]
    public required string ArtifactDigest { get; init; }

    [JsonPropertyName("signatureDigest")]
    public required string SignatureDigest { get; init; }

    [JsonPropertyName("label")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Label { get; init; }

    [JsonPropertyName("leafHash")]
    public required string LeafHash { get; init; }
}
