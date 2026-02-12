using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Sigil.Pe;

/// <summary>
/// Verifies Authenticode signatures embedded in PE files.
/// Pure managed implementation — works cross-platform.
/// </summary>
public static class AuthenticodeVerifier
{
    private const ushort ExpectedRevision = 0x0200;
    private const ushort ExpectedCertType = 0x0002;

    // RFC 3161 counter-signature OID used by Authenticode
    private const string Rfc3161CounterSignatureOid = "1.3.6.1.4.1.311.3.3.1";

    public static AuthenticodeResult<AuthenticodeVerifyResult> Verify(ReadOnlySpan<byte> peBytes)
    {
        // 1. Parse PE
        var parseResult = PeFile.Parse(peBytes);
        if (!parseResult.IsSuccess)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                parseResult.ErrorKind, parseResult.ErrorMessage);

        var peFile = parseResult.Value;

        // 2. Check certificate table exists
        if (peFile.CertTableSize == 0 || peFile.CertTableFileOffset == 0)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Ok(new AuthenticodeVerifyResult
            {
                IsValid = false,
                DigestAlgorithm = "",
                SubjectName = "",
                IssuerName = "",
                Thumbprint = "",
                Error = "No Authenticode signature found."
            });

        // 3. Extract WIN_CERTIFICATE
        int certOffset = (int)peFile.CertTableFileOffset;
        int certEnd = certOffset + (int)peFile.CertTableSize;
        if (certEnd > peBytes.Length || certOffset + 8 > peBytes.Length)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                AuthenticodeErrorKind.InvalidSignature,
                "Certificate table extends beyond file bounds.");

        uint dwLength = BinaryPrimitives.ReadUInt32LittleEndian(peBytes[certOffset..]);
        ushort wRevision = BinaryPrimitives.ReadUInt16LittleEndian(peBytes[(certOffset + 4)..]);
        ushort wCertificateType = BinaryPrimitives.ReadUInt16LittleEndian(peBytes[(certOffset + 6)..]);

        if (wRevision != ExpectedRevision)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                AuthenticodeErrorKind.InvalidSignature,
                $"Unsupported WIN_CERTIFICATE revision: 0x{wRevision:X4} (expected 0x0200).");

        if (wCertificateType != ExpectedCertType)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                AuthenticodeErrorKind.InvalidSignature,
                $"Unsupported WIN_CERTIFICATE type: 0x{wCertificateType:X4} (expected PKCS#7).");

        // Extract PKCS#7 bytes
        int pkcs7Length = (int)dwLength - 8;
        if (pkcs7Length <= 0 || certOffset + 8 + pkcs7Length > peBytes.Length)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                AuthenticodeErrorKind.InvalidSignature,
                "Invalid WIN_CERTIFICATE length.");

        byte[] pkcs7Bytes = peBytes.Slice(certOffset + 8, pkcs7Length).ToArray();

        // 4. Decode SignedCms (content is embedded, not detached)
        SignedCms signedCms;
        try
        {
            signedCms = new SignedCms();
            signedCms.Decode(pkcs7Bytes);
        }
        catch (CryptographicException ex)
        {
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                AuthenticodeErrorKind.InvalidSignature,
                $"Failed to decode PKCS#7 signature: {ex.Message}");
        }

        // 5. Recompute Authenticode hash (excluding cert table)
        var hashResult = AuthenticodeHasher.ComputeHash(peBytes, peFile, HashAlgorithmName.SHA256);
        if (!hashResult.IsSuccess)
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                hashResult.ErrorKind, hashResult.ErrorMessage);

        byte[] recomputedDigest = hashResult.Value;

        // 6. Parse SpcIndirectDataContent and extract embedded digest
        byte[] spcContent = signedCms.ContentInfo.Content;
        byte[] embeddedDigest;
        string algorithmOid;
        try
        {
            (embeddedDigest, algorithmOid) = SpcIndirectDataBuilder.Parse(spcContent);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return AuthenticodeResult<AuthenticodeVerifyResult>.Fail(
                AuthenticodeErrorKind.InvalidSignature,
                $"Failed to parse SpcIndirectDataContent: {ex.Message}");
        }

        // 7. Compare recomputed digest with embedded digest
        if (!CryptographicOperations.FixedTimeEquals(recomputedDigest, embeddedDigest))
        {
            return AuthenticodeResult<AuthenticodeVerifyResult>.Ok(new AuthenticodeVerifyResult
            {
                IsValid = false,
                DigestAlgorithm = OidToName(algorithmOid),
                SubjectName = "",
                IssuerName = "",
                Thumbprint = "",
                Error = "Authenticode digest mismatch — the PE file has been tampered with."
            });
        }

        // 8. Verify CMS cryptographic signature
        try
        {
            signedCms.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException ex)
        {
            return AuthenticodeResult<AuthenticodeVerifyResult>.Ok(new AuthenticodeVerifyResult
            {
                IsValid = false,
                DigestAlgorithm = OidToName(algorithmOid),
                SubjectName = "",
                IssuerName = "",
                Thumbprint = "",
                Error = $"CMS signature verification failed: {ex.Message}"
            });
        }

        // 9. Extract signer certificate info
        var signerInfo = signedCms.SignerInfos[0];
        var signerCert = signerInfo.Certificate;
        string subjectName = signerCert?.Subject ?? "";
        string issuerName = signerCert?.Issuer ?? "";
        string thumbprint = signerCert?.Thumbprint ?? "";

        // 10. Check for RFC 3161 counter-signature (timestamp)
        DateTimeOffset? timestampUtc = TryExtractTimestamp(signerInfo);

        return AuthenticodeResult<AuthenticodeVerifyResult>.Ok(new AuthenticodeVerifyResult
        {
            IsValid = true,
            DigestAlgorithm = OidToName(algorithmOid),
            SubjectName = subjectName,
            IssuerName = issuerName,
            Thumbprint = thumbprint,
            TimestampUtc = timestampUtc
        });
    }

    private static DateTimeOffset? TryExtractTimestamp(SignerInfo signerInfo)
    {
        foreach (var attr in signerInfo.UnsignedAttributes)
        {
            if (attr.Oid?.Value == Rfc3161CounterSignatureOid)
            {
                try
                {
                    // The attribute value is an RFC 3161 TSTInfo wrapped in CMS
                    var timestampCms = new SignedCms();
                    timestampCms.Decode(attr.Values[0].RawData);
                    var tstInfo = Rfc3161TimestampToken.TryDecode(timestampCms.Encode(), out var token, out _);
                    if (tstInfo && token is not null)
                    {
                        return token.TokenInfo.Timestamp;
                    }
                }
                catch (CryptographicException)
                {
                    // Timestamp present but couldn't be parsed
                }
            }
        }
        return null;
    }

    private static string OidToName(string oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => oid
    };
}
