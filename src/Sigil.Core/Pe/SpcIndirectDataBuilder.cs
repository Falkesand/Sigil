using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Sigil.Pe;

/// <summary>
/// Builds and parses SpcIndirectDataContent structures for Authenticode signatures.
/// Uses System.Formats.Asn1.AsnWriter for DER encoding.
/// </summary>
public static class SpcIndirectDataBuilder
{
    // Microsoft Authenticode OIDs
    public const string SpcIndirectDataOid = "1.3.6.1.4.1.311.2.1.4";
    public const string SpcPeImageDataOid = "1.3.6.1.4.1.311.2.1.15";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// Builds DER-encoded SpcIndirectDataContent for Authenticode signing.
    /// Structure:
    ///   SEQUENCE {
    ///     SEQUENCE {                             -- SpcAttributeTypeAndOptionalValue
    ///       OID 1.3.6.1.4.1.311.2.1.15          -- SpcPeImageDataObj
    ///       [0] SEQUENCE {                       -- SpcPeImageData (IMPLICIT)
    ///         BIT STRING (flags = 0)
    ///         [0] [0] BMP ""                     -- SpcLink file (obsolete)
    ///       }
    ///     }
    ///     SEQUENCE {                             -- DigestInfo
    ///       SEQUENCE { OID sha256, NULL }        -- AlgorithmIdentifier
    ///       OCTET STRING (digest)
    ///     }
    ///   }
    /// </summary>
    public static byte[] Build(byte[] authenticodeDigest, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(authenticodeDigest);

        string algorithmOid = GetAlgorithmOid(hashAlgorithm);

        var writer = new AsnWriter(AsnEncodingRules.DER);

        // Outer SEQUENCE
        writer.PushSequence();

        // SpcAttributeTypeAndOptionalValue
        writer.PushSequence();
        writer.WriteObjectIdentifier(SpcPeImageDataOid);

        // SpcPeImageData — [0] IMPLICIT SEQUENCE
        var implicitTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        writer.PushSequence(implicitTag);

        // Flags: BIT STRING with 0 padding bits and value 0
        writer.WriteBitString(ReadOnlySpan<byte>.Empty);

        // SpcLink: [0] CONSTRUCTED { [0] IMPLICIT BMP STRING "" }
        // This encodes the obsolete "file" link as an empty BMP string
        var spcLinkTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        writer.PushSetOf(spcLinkTag);
        var bmpTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: false);
        writer.WriteCharacterString(UniversalTagNumber.BMPString, "", bmpTag);
        writer.PopSetOf(spcLinkTag);

        writer.PopSequence(implicitTag);
        writer.PopSequence(); // End SpcAttributeTypeAndOptionalValue

        // DigestInfo
        writer.PushSequence();

        // AlgorithmIdentifier
        writer.PushSequence();
        writer.WriteObjectIdentifier(algorithmOid);
        writer.WriteNull();
        writer.PopSequence();

        // Digest
        writer.WriteOctetString(authenticodeDigest);

        writer.PopSequence(); // End DigestInfo

        writer.PopSequence(); // End outer SEQUENCE

        return writer.Encode();
    }

    /// <summary>
    /// Parses SpcIndirectDataContent to extract the digest and algorithm OID.
    /// </summary>
    public static (byte[] digest, string algorithmOid) Parse(byte[] spcContent)
    {
        ArgumentNullException.ThrowIfNull(spcContent);

        var reader = new AsnReader(spcContent, AsnEncodingRules.DER);

        // Outer SEQUENCE
        var outerSequence = reader.ReadSequence();

        // Skip SpcAttributeTypeAndOptionalValue
        outerSequence.ReadSequence();

        // DigestInfo SEQUENCE
        var digestInfo = outerSequence.ReadSequence();

        // AlgorithmIdentifier SEQUENCE
        var algorithmId = digestInfo.ReadSequence();
        string oid = algorithmId.ReadObjectIdentifier();

        // Digest OCTET STRING
        byte[] digest = digestInfo.ReadOctetString();

        return (digest, oid);
    }

    private static string GetAlgorithmOid(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return Sha256Oid;

        throw new NotSupportedException(
            $"Hash algorithm '{hashAlgorithm.Name}' is not supported for Authenticode. Use SHA-256.");
    }
}
