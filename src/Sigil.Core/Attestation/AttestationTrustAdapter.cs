using Sigil.Signing;

namespace Sigil.Attestation;

/// <summary>
/// Adapts <see cref="AttestationVerificationResult"/> to <see cref="VerificationResult"/>
/// so the existing <see cref="Trust.TrustEvaluator"/> can evaluate attestation signatures unchanged.
/// </summary>
public static class AttestationTrustAdapter
{
    public static VerificationResult ToVerificationResult(AttestationVerificationResult attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);

        var signatures = attestation.Signatures.Select(s => new SignatureVerificationResult
        {
            KeyId = s.KeyId,
            IsValid = s.IsValid,
            Algorithm = s.Algorithm,
            Error = s.Error,
            TimestampInfo = s.TimestampInfo
        }).ToList();

        return new VerificationResult
        {
            ArtifactDigestMatch = attestation.SubjectDigestMatch,
            Signatures = signatures
        };
    }
}
