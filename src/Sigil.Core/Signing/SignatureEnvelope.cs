using System.Text.Json.Serialization;

namespace Sigil.Signing;

/// <summary>
/// Detached signature envelope. Format-agnostic — works with any artifact.
/// </summary>
public sealed class SignatureEnvelope
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = "1.0";

    [JsonPropertyName("subject")]
    public required SubjectDescriptor Subject { get; init; }

    [JsonPropertyName("signatures")]
    public List<SignatureEntry> Signatures { get; init; } = [];
}

public sealed class SubjectDescriptor
{
    [JsonPropertyName("digests")]
    public required Dictionary<string, string> Digests { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("mediaType")]
    public string? MediaType { get; init; }
}

public sealed class SignatureEntry
{
    [JsonPropertyName("keyId")]
    public required string KeyId { get; init; }

    [JsonPropertyName("algorithm")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("value")]
    public required string Value { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }

    [JsonPropertyName("label")]
    public string? Label { get; init; }
}
