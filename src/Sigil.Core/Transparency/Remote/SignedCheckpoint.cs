using System.Text.Json.Serialization;

namespace Sigil.Transparency.Remote;

public sealed class SignedCheckpoint
{
    [JsonPropertyName("treeSize")]
    public required long TreeSize { get; init; }

    [JsonPropertyName("rootHash")]
    public required string RootHash { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }

    [JsonPropertyName("signature")]
    public required string Signature { get; init; }
}
