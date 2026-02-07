using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class TrustScopes
{
    [JsonPropertyName("namePatterns")]
    public List<string>? NamePatterns { get; set; }

    [JsonPropertyName("labels")]
    public List<string>? Labels { get; set; }

    [JsonPropertyName("algorithms")]
    public List<string>? Algorithms { get; set; }
}
