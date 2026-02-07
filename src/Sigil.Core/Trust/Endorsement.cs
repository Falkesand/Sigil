using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class Endorsement
{
    [JsonPropertyName("endorser")]
    public required string Endorser { get; set; }

    [JsonPropertyName("endorsed")]
    public required string Endorsed { get; set; }

    [JsonPropertyName("statement")]
    public string? Statement { get; set; }

    [JsonPropertyName("scopes")]
    public TrustScopes? Scopes { get; set; }

    [JsonPropertyName("notAfter")]
    public string? NotAfter { get; set; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; set; }
}
