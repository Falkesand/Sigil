using System.Text.Json.Serialization;

namespace Sigil.Attestation;

public sealed class DsseEnvelope
{
    [JsonPropertyName("payloadType")]
    public string PayloadType { get; init; } = "application/vnd.in-toto+json";

    [JsonPropertyName("payload")]
    public required string Payload { get; init; }

    [JsonPropertyName("signatures")]
    public List<DsseSignature> Signatures { get; init; } = [];
}
