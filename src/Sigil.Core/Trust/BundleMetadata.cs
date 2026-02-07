using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class BundleMetadata
{
    [JsonPropertyName("name")]
    public required string Name { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("created")]
    public required string Created { get; set; }
}
