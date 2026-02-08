using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Attestation;

public sealed class InTotoStatement
{
    [JsonPropertyName("_type")]
    public string Type { get; init; } = "https://in-toto.io/Statement/v1";

    [JsonPropertyName("subject")]
    public required List<InTotoSubject> Subject { get; init; }

    [JsonPropertyName("predicateType")]
    public required string PredicateType { get; init; }

    [JsonPropertyName("predicate")]
    public JsonElement? Predicate { get; init; }
}
