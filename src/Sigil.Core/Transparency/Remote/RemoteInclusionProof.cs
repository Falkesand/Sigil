using System.Text.Json.Serialization;

namespace Sigil.Transparency.Remote;

public sealed class RemoteInclusionProof
{
    [JsonPropertyName("leafIndex")]
    public required long LeafIndex { get; init; }

    [JsonPropertyName("treeSize")]
    public required long TreeSize { get; init; }

    [JsonPropertyName("rootHash")]
    public required string RootHash { get; init; }

    [JsonPropertyName("hashes")]
    public required IReadOnlyList<string> Hashes { get; init; }
}
