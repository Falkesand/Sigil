using System.Formats.Asn1;

namespace Sigil.Crypto;

/// <summary>
/// Detects the signing algorithm from DER-encoded SPKI or PKCS#8 key material
/// by parsing the AlgorithmIdentifier OID.
/// Uses System.Formats.Asn1 (in-box since .NET 5) — no external dependencies.
/// </summary>
public static class AlgorithmDetector
{
    // EC key algorithm OID: 1.2.840.10045.2.1
    private const string OidEcPublicKey = "1.2.840.10045.2.1";

    // EC curve parameter OIDs
    private const string OidNistP256 = "1.2.840.10045.3.1.7";
    private const string OidNistP384 = "1.3.132.0.34";

    // RSA algorithm OID: 1.2.840.113549.1.1.1
    private const string OidRsaEncryption = "1.2.840.113549.1.1.1";

    // Ed25519 algorithm OID: 1.3.101.112
    private const string OidEd25519 = "1.3.101.112";

    /// <summary>
    /// Detects the signing algorithm from a DER-encoded SubjectPublicKeyInfo (SPKI).
    /// </summary>
    public static SigningAlgorithm DetectFromSpki(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);

        if (spki.Length == 0)
            throw new NotSupportedException("Cannot detect algorithm from empty SPKI bytes.");

        return ParseAlgorithmIdentifier(spki);
    }

    /// <summary>
    /// Detects the signing algorithm from a DER-encoded PKCS#8 PrivateKeyInfo.
    /// </summary>
    public static SigningAlgorithm DetectFromPkcs8Der(byte[] pkcs8)
    {
        ArgumentNullException.ThrowIfNull(pkcs8);

        if (pkcs8.Length == 0)
            throw new NotSupportedException("Cannot detect algorithm from empty PKCS#8 bytes.");

        // PKCS#8 PrivateKeyInfo ::= SEQUENCE {
        //   version               INTEGER,
        //   privateKeyAlgorithm   AlgorithmIdentifier,
        //   privateKey            OCTET STRING
        // }
        var reader = new AsnReader(pkcs8, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        // Skip version INTEGER
        sequence.ReadInteger();

        // Now read the AlgorithmIdentifier
        return ReadAlgorithmIdentifier(sequence);
    }

    /// <summary>
    /// Parses the AlgorithmIdentifier from the start of a SEQUENCE
    /// (works for both SPKI and PKCS#8 after version is skipped).
    /// </summary>
    private static SigningAlgorithm ParseAlgorithmIdentifier(byte[] derBytes)
    {
        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm   AlgorithmIdentifier,
        //   subjectPublicKey  BIT STRING
        // }
        var reader = new AsnReader(derBytes, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        return ReadAlgorithmIdentifier(sequence);
    }

    private static SigningAlgorithm ReadAlgorithmIdentifier(AsnReader parentSequence)
    {
        // AlgorithmIdentifier ::= SEQUENCE {
        //   algorithm   OBJECT IDENTIFIER,
        //   parameters  ANY DEFINED BY algorithm OPTIONAL
        // }
        var algIdSequence = parentSequence.ReadSequence();
        var algorithmOid = algIdSequence.ReadObjectIdentifier();

        return algorithmOid switch
        {
            OidEcPublicKey => DetectEcCurve(algIdSequence),
            OidRsaEncryption => SigningAlgorithm.Rsa,
            OidEd25519 => SigningAlgorithm.Ed25519,
            _ => throw new NotSupportedException($"Unsupported algorithm OID: {algorithmOid}")
        };
    }

    private static SigningAlgorithm DetectEcCurve(AsnReader algIdSequence)
    {
        // For EC keys, the parameters field contains the curve OID
        var curveOid = algIdSequence.ReadObjectIdentifier();

        return curveOid switch
        {
            OidNistP256 => SigningAlgorithm.ECDsaP256,
            OidNistP384 => SigningAlgorithm.ECDsaP384,
            _ => throw new NotSupportedException($"Unsupported EC curve OID: {curveOid}")
        };
    }
}
