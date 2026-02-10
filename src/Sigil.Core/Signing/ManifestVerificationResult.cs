namespace Sigil.Signing;

/// <summary>
/// Result of verifying all files and signatures in a manifest envelope.
/// </summary>
public sealed class ManifestVerificationResult
{
    public required IReadOnlyList<FileVerificationResult> FileResults { get; init; }
    public required IReadOnlyList<SignatureVerificationResult> Signatures { get; init; }

    public bool AllDigestsMatch => FileResults.All(f => f.DigestMatch);
    public bool AllSignaturesValid => AllDigestsMatch && Signatures.All(s => s.IsValid);
    public bool AnySignatureValid => AllDigestsMatch && Signatures.Any(s => s.IsValid);
}
