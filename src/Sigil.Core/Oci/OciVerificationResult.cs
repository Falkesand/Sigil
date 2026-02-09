using Sigil.Signing;

namespace Sigil.Oci;

/// <summary>
/// Result of verifying all signatures on an OCI image.
/// </summary>
public sealed class OciVerificationResult
{
    public required string ManifestDigest { get; init; }
    public required IReadOnlyList<VerificationResult> SignatureResults { get; init; }

    public bool AllSignaturesValid =>
        SignatureResults.Count > 0 && SignatureResults.All(r => r.AllSignaturesValid);

    public bool AnySignatureValid =>
        SignatureResults.Any(r => r.AnySignatureValid);

    public int SignatureCount => SignatureResults.Count;
}
