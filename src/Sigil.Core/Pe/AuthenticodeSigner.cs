using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Pe;

/// <summary>
/// Signs PE (Portable Executable) files with Authenticode signatures.
/// Produces both an embedded Authenticode signature in the PE and a detached Sigil .sig.json envelope.
/// Pure managed implementation — works cross-platform.
/// </summary>
public static class AuthenticodeSigner
{
    private const ushort WinCertRevision = 0x0200;
    private const ushort WinCertTypePkcs7 = 0x0002;
    private const int WinCertAlignment = 8;

    /// <summary>
    /// Signs a PE binary with Authenticode. Produces signed PE bytes and a detached .sig.json envelope.
    /// </summary>
    public static AuthenticodeResult<AuthenticodeSignResult> Sign(
        byte[] peBytes,
        X509Certificate2 certificate,
        string? label = null,
        string? fileName = null)
    {
        ArgumentNullException.ThrowIfNull(peBytes);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
            return AuthenticodeResult<AuthenticodeSignResult>.Fail(
                AuthenticodeErrorKind.SigningFailed,
                "Certificate does not contain a private key.");

        // 1. Parse PE headers
        var parseResult = PeFile.Parse(peBytes);
        if (!parseResult.IsSuccess)
            return AuthenticodeResult<AuthenticodeSignResult>.Fail(
                parseResult.ErrorKind, parseResult.ErrorMessage);

        var peFile = parseResult.Value;

        // 2. Strip existing certificate table if present
        byte[] workingBytes;
        PeFile workingPe;
        if (peFile.CertTableSize > 0 && peFile.CertTableFileOffset > 0)
        {
            workingBytes = new byte[peFile.CertTableFileOffset];
            Array.Copy(peBytes, workingBytes, (int)peFile.CertTableFileOffset);

            // Zero out the cert table directory entry
            BinaryPrimitives.WriteUInt32LittleEndian(
                workingBytes.AsSpan(peFile.CertTableDirectoryOffset), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(
                workingBytes.AsSpan(peFile.CertTableDirectoryOffset + 4), 0);

            // Re-parse after stripping
            var reParseResult = PeFile.Parse(workingBytes);
            if (!reParseResult.IsSuccess)
                return AuthenticodeResult<AuthenticodeSignResult>.Fail(
                    reParseResult.ErrorKind, reParseResult.ErrorMessage);
            workingPe = reParseResult.Value;
        }
        else
        {
            workingBytes = (byte[])peBytes.Clone();
            workingPe = peFile;
        }

        // 3. Compute Authenticode hash
        var hashResult = AuthenticodeHasher.ComputeHash(workingBytes, workingPe, HashAlgorithmName.SHA256);
        if (!hashResult.IsSuccess)
            return AuthenticodeResult<AuthenticodeSignResult>.Fail(
                hashResult.ErrorKind, hashResult.ErrorMessage);

        byte[] authenticodeDigest = hashResult.Value;

        // 4. Build SpcIndirectDataContent
        byte[] spcBytes = SpcIndirectDataBuilder.Build(authenticodeDigest, HashAlgorithmName.SHA256);

        // 5. Create CMS (PKCS#7) signature
        byte[] pkcs7Bytes;
        try
        {
            var contentInfo = new ContentInfo(new Oid(SpcIndirectDataBuilder.SpcIndirectDataOid), spcBytes);
            var signedCms = new SignedCms(contentInfo, detached: false);

            var cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), // SHA-256
                IncludeOption = X509IncludeOption.WholeChain
            };

            signedCms.ComputeSignature(cmsSigner);
            pkcs7Bytes = signedCms.Encode();
        }
        catch (CryptographicException ex)
        {
            return AuthenticodeResult<AuthenticodeSignResult>.Fail(
                AuthenticodeErrorKind.SigningFailed,
                $"CMS signature computation failed: {ex.Message}");
        }

        // 6. Build WIN_CERTIFICATE structure
        int winCertLength = 8 + pkcs7Bytes.Length; // Header (8) + PKCS#7
        int paddedLength = AlignTo(winCertLength, WinCertAlignment);

        var winCert = new byte[paddedLength];
        BinaryPrimitives.WriteUInt32LittleEndian(winCert.AsSpan(0), (uint)winCertLength);
        BinaryPrimitives.WriteUInt16LittleEndian(winCert.AsSpan(4), WinCertRevision);
        BinaryPrimitives.WriteUInt16LittleEndian(winCert.AsSpan(6), WinCertTypePkcs7);
        pkcs7Bytes.AsSpan().CopyTo(winCert.AsSpan(8));

        // 7. Append WIN_CERTIFICATE to PE, update cert table directory
        uint certTableOffset = (uint)workingBytes.Length;
        uint certTableSize = (uint)paddedLength;

        var signedPe = new byte[workingBytes.Length + paddedLength];
        Array.Copy(workingBytes, signedPe, workingBytes.Length);
        Array.Copy(winCert, 0, signedPe, workingBytes.Length, paddedLength);

        // Update Certificate Table Data Directory entry
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedPe.AsSpan(workingPe.CertTableDirectoryOffset), certTableOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(
            signedPe.AsSpan(workingPe.CertTableDirectoryOffset + 4), certTableSize);

        // 8. Recalculate and write PE CheckSum
        uint checksum = PeChecksum.Compute(signedPe, workingPe.CheckSumOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(signedPe.AsSpan(workingPe.CheckSumOffset), checksum);

        // 9. Produce detached .sig.json envelope (over signed PE bytes for digest consistency)
        var envelope = BuildSigilEnvelope(signedPe, certificate, label, fileName ?? "pe-binary");

        return AuthenticodeResult<AuthenticodeSignResult>.Ok(new AuthenticodeSignResult
        {
            SignedPeBytes = signedPe,
            Envelope = envelope
        });
    }

    /// <summary>
    /// Async variant for vault/TSA scenarios.
    /// </summary>
    public static Task<AuthenticodeResult<AuthenticodeSignResult>> SignAsync(
        byte[] peBytes,
        X509Certificate2 certificate,
        string? label = null,
        string? fileName = null)
    {
        return Task.FromResult(Sign(peBytes, certificate, label, fileName));
    }

    /// <summary>
    /// Replaces the PKCS#7 bytes in a signed PE (used to inject timestamp after signing).
    /// </summary>
    internal static AuthenticodeResult<byte[]> ReplacePkcs7(byte[] signedPeBytes, byte[] newPkcs7Bytes)
    {
        var parseResult = PeFile.Parse(signedPeBytes);
        if (!parseResult.IsSuccess)
            return AuthenticodeResult<byte[]>.Fail(parseResult.ErrorKind, parseResult.ErrorMessage);

        var peFile = parseResult.Value;
        if (peFile.CertTableSize == 0)
            return AuthenticodeResult<byte[]>.Fail(
                AuthenticodeErrorKind.NoSignatureFound, "PE has no certificate table.");

        // Strip old cert table
        var stripped = new byte[peFile.CertTableFileOffset];
        Array.Copy(signedPeBytes, stripped, (int)peFile.CertTableFileOffset);

        // Zero cert table directory
        BinaryPrimitives.WriteUInt32LittleEndian(
            stripped.AsSpan(peFile.CertTableDirectoryOffset), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(
            stripped.AsSpan(peFile.CertTableDirectoryOffset + 4), 0);

        // Build new WIN_CERTIFICATE
        int winCertLength = 8 + newPkcs7Bytes.Length;
        int paddedLength = AlignTo(winCertLength, WinCertAlignment);
        var winCert = new byte[paddedLength];
        BinaryPrimitives.WriteUInt32LittleEndian(winCert.AsSpan(0), (uint)winCertLength);
        BinaryPrimitives.WriteUInt16LittleEndian(winCert.AsSpan(4), WinCertRevision);
        BinaryPrimitives.WriteUInt16LittleEndian(winCert.AsSpan(6), WinCertTypePkcs7);
        newPkcs7Bytes.AsSpan().CopyTo(winCert.AsSpan(8));

        // Append
        uint certTableOffset = (uint)stripped.Length;
        var result = new byte[stripped.Length + paddedLength];
        Array.Copy(stripped, result, stripped.Length);
        Array.Copy(winCert, 0, result, stripped.Length, paddedLength);

        // Update directory
        BinaryPrimitives.WriteUInt32LittleEndian(
            result.AsSpan(peFile.CertTableDirectoryOffset), certTableOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(
            result.AsSpan(peFile.CertTableDirectoryOffset + 4), (uint)paddedLength);

        // Recalculate checksum
        uint checksum = PeChecksum.Compute(result, peFile.CheckSumOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(peFile.CheckSumOffset), checksum);

        return AuthenticodeResult<byte[]>.Ok(result);
    }

    private static SignatureEnvelope BuildSigilEnvelope(
        byte[] peBytes, X509Certificate2 certificate, string? label, string fileName)
    {
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(peBytes);

        using var certSigner = CertificateKeySigner.Create(certificate);
        var fingerprint = KeyFingerprint.Compute(certSigner.PublicKey);

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = fileName,
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                }
            }
        };

        ArtifactSigner.AppendSignature(envelope, peBytes, certSigner, fingerprint, label);
        return envelope;
    }

    private static int AlignTo(int value, int alignment)
    {
        return (value + alignment - 1) / alignment * alignment;
    }
}
