using System.Text.Json.Serialization;

namespace Sigil.Attestation;

public sealed class InTotoSubject
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("digest")]
    public required Dictionary<string, string> Digest { get; init; }
}
