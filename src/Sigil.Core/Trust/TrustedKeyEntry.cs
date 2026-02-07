using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class TrustedKeyEntry
{
    [JsonPropertyName("fingerprint")]
    public required string Fingerprint { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("scopes")]
    public TrustScopes? Scopes { get; set; }

    [JsonPropertyName("notAfter")]
    public string? NotAfter { get; set; }
}
