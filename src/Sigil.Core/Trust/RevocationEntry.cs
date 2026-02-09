using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class RevocationEntry
{
    [JsonPropertyName("fingerprint")]
    public required string Fingerprint { get; set; }

    [JsonPropertyName("revokedAt")]
    public required string RevokedAt { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}
