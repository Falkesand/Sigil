using Sigil.Attestation;
using Sigil.Signing;

namespace Sigil.Policy;

public sealed class PolicyContext
{
    public required VerificationResult Verification { get; init; }
    public SignatureEnvelope? Envelope { get; init; }
    public DsseEnvelope? DsseEnvelope { get; init; }
    public InTotoStatement? Statement { get; init; }
    public string? ArtifactName { get; init; }
    public string? BasePath { get; init; }
    public ManifestEnvelope? ManifestEnvelope { get; init; }
}
