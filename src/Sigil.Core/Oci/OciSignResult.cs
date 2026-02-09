namespace Sigil.Oci;

/// <summary>
/// Result of signing an OCI image.
/// </summary>
public sealed class OciSignResult
{
    public required string ManifestDigest { get; init; }
    public required string SignatureDigest { get; init; }
    public required string KeyId { get; init; }
    public required string Algorithm { get; init; }
}
