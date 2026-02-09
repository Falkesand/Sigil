using Sigil.Crypto;

namespace Sigil.Oci;

/// <summary>
/// Builds OCI artifact manifests for storing Sigil signatures as OCI referrers.
/// </summary>
public static class SignatureManifestBuilder
{
    /// <summary>
    /// Empty OCI config: {} (2 bytes), well-known digest.
    /// </summary>
    public static readonly byte[] EmptyConfig = "{}"u8.ToArray();

    public static readonly string EmptyConfigDigest =
        $"sha256:{HashAlgorithms.Sha256Hex(EmptyConfig)}";

    /// <summary>
    /// Builds an OCI artifact manifest that references the signed image manifest
    /// and contains the signature envelope as a layer.
    /// </summary>
    public static OciManifest Build(OciDescriptor subjectDescriptor, byte[] envelopeBytes)
    {
        ArgumentNullException.ThrowIfNull(subjectDescriptor);
        ArgumentNullException.ThrowIfNull(envelopeBytes);

        var envelopeDigest = $"sha256:{HashAlgorithms.Sha256Hex(envelopeBytes)}";

        var config = new OciDescriptor
        {
            MediaType = OciMediaTypes.OciEmptyConfig,
            Digest = EmptyConfigDigest,
            Size = EmptyConfig.Length
        };

        var layer = new OciDescriptor
        {
            MediaType = OciMediaTypes.SigilSignature,
            Digest = envelopeDigest,
            Size = envelopeBytes.Length
        };

        return new OciManifest
        {
            MediaType = OciMediaTypes.OciManifestV1,
            ArtifactType = OciMediaTypes.SigilSignature,
            Config = config,
            Layers = [layer],
            Subject = subjectDescriptor
        };
    }
}
