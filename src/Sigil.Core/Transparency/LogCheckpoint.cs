using System.Text.Json.Serialization;

namespace Sigil.Transparency;

public sealed class LogCheckpoint
{
    [JsonPropertyName("treeSize")]
    public required long TreeSize { get; init; }

    [JsonPropertyName("rootHash")]
    public required string RootHash { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }
}
