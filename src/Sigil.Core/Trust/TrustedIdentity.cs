using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class TrustedIdentity
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; set; }

    [JsonPropertyName("subjectPattern")]
    public required string SubjectPattern { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("notAfter")]
    public string? NotAfter { get; set; }
}
