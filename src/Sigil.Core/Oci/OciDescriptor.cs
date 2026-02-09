using System.Text.Json.Serialization;

namespace Sigil.Oci;

/// <summary>
/// OCI content descriptor (image manifest, config, layer, or subject).
/// </summary>
public sealed class OciDescriptor
{
    [JsonPropertyName("mediaType")]
    public required string MediaType { get; init; }

    [JsonPropertyName("digest")]
    public required string Digest { get; init; }

    [JsonPropertyName("size")]
    public required long Size { get; init; }

    [JsonPropertyName("artifactType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ArtifactType { get; init; }

    [JsonPropertyName("annotations")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Annotations { get; init; }
}
