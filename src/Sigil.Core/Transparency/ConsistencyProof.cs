using System.Text.Json.Serialization;

namespace Sigil.Transparency;

public sealed class ConsistencyProof
{
    [JsonPropertyName("oldSize")]
    public required long OldSize { get; init; }

    [JsonPropertyName("newSize")]
    public required long NewSize { get; init; }

    [JsonPropertyName("oldRootHash")]
    public required string OldRootHash { get; init; }

    [JsonPropertyName("newRootHash")]
    public required string NewRootHash { get; init; }

    [JsonPropertyName("hashes")]
    public required IReadOnlyList<string> Hashes { get; init; }
}
