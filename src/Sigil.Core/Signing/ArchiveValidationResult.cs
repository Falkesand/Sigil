namespace Sigil.Signing;

/// <summary>
/// Result of verifying all entries and signatures in an archive envelope.
/// </summary>
public sealed class ArchiveValidationResult
{
    public required IReadOnlyList<ArchiveEntryValidation> Entries { get; init; }
    public required IReadOnlyList<SignatureVerificationResult> Signatures { get; init; }
    public required IReadOnlyList<string> ExtraEntries { get; init; }

    public bool AllDigestsMatch => Entries.Count > 0 && Entries.All(e => e.DigestMatch);
    public bool AllSignaturesValid => AllDigestsMatch && Signatures.All(s => s.IsValid);
    public bool AnySignatureValid => AllDigestsMatch && Signatures.Any(s => s.IsValid);
}
