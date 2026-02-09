using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Oci;

/// <summary>
/// OCI image manifest v1 model. Supports both OCI and Docker manifest formats.
/// </summary>
public sealed class OciManifest
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; init; } = 2;

    [JsonPropertyName("mediaType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MediaType { get; init; }

    [JsonPropertyName("artifactType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ArtifactType { get; init; }

    [JsonPropertyName("config")]
    public required OciDescriptor Config { get; init; }

    [JsonPropertyName("layers")]
    public required List<OciDescriptor> Layers { get; init; }

    [JsonPropertyName("subject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public OciDescriptor? Subject { get; init; }

    [JsonPropertyName("annotations")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Annotations { get; init; }

    public string Serialize() => JsonSerializer.Serialize(this, SerializerOptions);

    public static OciResult<OciManifest> Deserialize(string json)
    {
        try
        {
            var manifest = JsonSerializer.Deserialize<OciManifest>(json, SerializerOptions);
            if (manifest is null)
                return OciResult<OciManifest>.Fail(OciErrorKind.InvalidManifest, "Manifest deserialized to null.");

            return OciResult<OciManifest>.Ok(manifest);
        }
        catch (JsonException ex)
        {
            return OciResult<OciManifest>.Fail(OciErrorKind.InvalidManifest, $"Malformed manifest JSON: {ex.Message}");
        }
    }

    public static OciResult<OciManifest> Deserialize(byte[] bytes)
    {
        return Deserialize(System.Text.Encoding.UTF8.GetString(bytes));
    }
}
