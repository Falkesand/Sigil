namespace Sigil.Attestation;

/// <summary>
/// Result of verifying all signatures in a DSSE attestation envelope,
/// including subject digest verification against the artifact.
/// </summary>
public sealed class AttestationVerificationResult
{
    public required bool SubjectDigestMatch { get; init; }
    public required IReadOnlyList<AttestationSignatureResult> Signatures { get; init; }
    public InTotoStatement? Statement { get; init; }

    public bool AllSignaturesValid => SubjectDigestMatch && Signatures.All(s => s.IsValid);
    public bool AnySignatureValid => SubjectDigestMatch && Signatures.Any(s => s.IsValid);
}
