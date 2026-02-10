using System.Text.Json.Serialization;

namespace Sigil.Trust;

public sealed class TrustBundle
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0";

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "trust-bundle";

    [JsonPropertyName("metadata")]
    public required BundleMetadata Metadata { get; set; }

    [JsonPropertyName("keys")]
    public List<TrustedKeyEntry> Keys { get; set; } = [];

    [JsonPropertyName("endorsements")]
    public List<Endorsement> Endorsements { get; set; } = [];

    [JsonPropertyName("revocations")]
    public List<RevocationEntry> Revocations { get; set; } = [];

    [JsonPropertyName("identities")]
    public List<TrustedIdentity> Identities { get; set; } = [];

    [JsonPropertyName("signature")]
    public BundleSignature? Signature { get; set; }
}
