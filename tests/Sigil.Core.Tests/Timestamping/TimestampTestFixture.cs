using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Sigil.Core.Tests.Timestamping;

/// <summary>
/// Creates synthetic RFC 3161 timestamp tokens for unit tests.
/// Uses a self-signed RSA certificate to sign the CMS structure.
/// </summary>
internal static class TimestampTestFixture
{
    /// <summary>
    /// Creates a valid RFC 3161 timestamp token (DER-encoded CMS) for the given data.
    /// The token hash is computed as SHA-256(data).
    /// </summary>
    public static byte[] CreateTimestampToken(byte[] data, DateTimeOffset? timestamp = null)
    {
        var ts = timestamp ?? DateTimeOffset.UtcNow;
        var hash = SHA256.HashData(data);
        return CreateTimestampTokenFromHash(hash, ts);
    }

    /// <summary>
    /// Creates a valid RFC 3161 timestamp token (DER-encoded CMS) for the given hash.
    /// </summary>
    public static byte[] CreateTimestampTokenFromHash(byte[] hash, DateTimeOffset? timestamp = null)
    {
        var ts = timestamp ?? DateTimeOffset.UtcNow;

        // Build TSTInfo (RFC 3161 §2.4.2)
        var tstInfoBytes = BuildTstInfo(hash, ts);

        // Create self-signed certificate for TSA
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test TSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.8") }, critical: true)); // id-kp-timeStamping

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        // Wrap TSTInfo in CMS SignedData (content type id-smime-ct-TSTInfo = 1.2.840.113549.1.9.16.1.4)
        var contentInfo = new ContentInfo(new Oid("1.2.840.113549.1.9.16.1.4"), tstInfoBytes);
        var cms = new SignedCms(contentInfo, detached: false);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") // SHA-256
        };
        signer.SignedAttributes.Add(new Pkcs9SigningTime(ts.DateTime));
        cms.ComputeSignature(signer);

        return cms.Encode();
    }

    /// <summary>
    /// Creates a timestamp token with a deliberately wrong hash for negative testing.
    /// </summary>
    public static byte[] CreateMismatchedToken(DateTimeOffset? timestamp = null)
    {
        var wrongHash = SHA256.HashData([0xFF, 0xFF, 0xFF, 0xFF]);
        return CreateTimestampTokenFromHash(wrongHash, timestamp);
    }

    private static byte[] BuildTstInfo(byte[] hash, DateTimeOffset timestamp)
    {
        // TSTInfo ::= SEQUENCE {
        //   version        INTEGER { v1(1) },
        //   policy         OBJECT IDENTIFIER,
        //   messageImprint MessageImprint,
        //   serialNumber   INTEGER,
        //   genTime        GeneralizedTime,
        //   ...
        // }
        // MessageImprint ::= SEQUENCE {
        //   hashAlgorithm  AlgorithmIdentifier,
        //   hashedMessage  OCTET STRING
        // }
        var writer = new AsnWriter(AsnEncodingRules.DER);

        writer.PushSequence();

        // version INTEGER v1(1)
        writer.WriteInteger(1);

        // policy OID (test policy)
        writer.WriteObjectIdentifier("1.3.6.1.4.1.99999.1");

        // messageImprint SEQUENCE
        writer.PushSequence();
        // hashAlgorithm AlgorithmIdentifier SEQUENCE
        writer.PushSequence();
        writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
        writer.WriteNull();
        writer.PopSequence();
        // hashedMessage OCTET STRING
        writer.WriteOctetString(hash);
        writer.PopSequence();

        // serialNumber INTEGER
        writer.WriteInteger(RandomNumberGenerator.GetInt32(1, int.MaxValue));

        // genTime GeneralizedTime
        writer.WriteGeneralizedTime(timestamp);

        writer.PopSequence();

        return writer.Encode();
    }
}
