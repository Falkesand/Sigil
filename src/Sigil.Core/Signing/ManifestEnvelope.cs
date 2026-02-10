using System.Text.Json.Serialization;

namespace Sigil.Signing;

/// <summary>
/// Manifest signature envelope. Signs multiple files in one operation
/// with a shared signature covering all subject digests atomically.
/// </summary>
public sealed class ManifestEnvelope
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = "1.0";

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = "manifest";

    [JsonPropertyName("subjects")]
    public required List<SubjectDescriptor> Subjects { get; init; }

    [JsonPropertyName("signatures")]
    public List<SignatureEntry> Signatures { get; init; } = [];
}
