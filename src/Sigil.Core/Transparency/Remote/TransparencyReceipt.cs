using System.Text.Json.Serialization;

namespace Sigil.Transparency.Remote;

public sealed class TransparencyReceipt
{
    [JsonPropertyName("logUrl")]
    public required string LogUrl { get; init; }

    [JsonPropertyName("logIndex")]
    public required long LogIndex { get; init; }

    [JsonPropertyName("signedCheckpoint")]
    public required string SignedCheckpoint { get; init; }

    [JsonPropertyName("inclusionProof")]
    public required RemoteInclusionProof InclusionProof { get; init; }
}
