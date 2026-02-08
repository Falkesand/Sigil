using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Sigil.Timestamping;

/// <summary>
/// Validates RFC 3161 timestamp tokens against signature value bytes.
/// </summary>
public static class TimestampValidator
{
    private static readonly Oid Sha256Oid = new("2.16.840.1.101.3.4.2.1");

    public static TimestampVerificationInfo Validate(
        string base64TimestampToken, byte[] signatureValueBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64TimestampToken);
        ArgumentNullException.ThrowIfNull(signatureValueBytes);

        try
        {
            var tokenBytes = Convert.FromBase64String(base64TimestampToken);

            // Try the standard API first
            if (Rfc3161TimestampToken.TryDecode(tokenBytes, out var token, out _))
            {
                return ValidateToken(token, signatureValueBytes);
            }

            // Fallback: parse as CMS and try to extract TSTInfo
            var cms = new SignedCms();
            cms.Decode(tokenBytes);
            cms.CheckSignature(verifySignatureOnly: true);

            // Try to decode the CMS content as TSTInfo
            if (Rfc3161TimestampTokenInfo.TryDecode(cms.ContentInfo.Content, out var tokenInfo, out _))
            {
                return ValidateTokenInfo(tokenInfo, signatureValueBytes);
            }

            return new TimestampVerificationInfo
            {
                Timestamp = default,
                IsValid = false,
                Error = "Failed to decode RFC 3161 timestamp token."
            };
        }
        catch (FormatException)
        {
            return new TimestampVerificationInfo
            {
                Timestamp = default,
                IsValid = false,
                Error = "Invalid base64 encoding for timestamp token."
            };
        }
        catch (CryptographicException ex)
        {
            return new TimestampVerificationInfo
            {
                Timestamp = default,
                IsValid = false,
                Error = $"Timestamp token cryptographic error: {ex.Message}"
            };
        }
    }

    private static TimestampVerificationInfo ValidateToken(
        Rfc3161TimestampToken token, byte[] signatureValueBytes)
    {
        var expectedHash = SHA256.HashData(signatureValueBytes);
        var tokenInfo = token.TokenInfo;

        // Verify the hash algorithm is SHA-256
        if (tokenInfo.HashAlgorithmId.Value != Sha256Oid.Value)
        {
            return new TimestampVerificationInfo
            {
                Timestamp = tokenInfo.Timestamp,
                IsValid = false,
                Error = $"Unsupported timestamp hash algorithm: {tokenInfo.HashAlgorithmId.Value}. Expected SHA-256."
            };
        }

        if (!tokenInfo.GetMessageHash().Span.SequenceEqual(expectedHash))
        {
            return new TimestampVerificationInfo
            {
                Timestamp = tokenInfo.Timestamp,
                IsValid = false,
                Error = "Timestamp token hash does not match signature bytes."
            };
        }

        // Verify the CMS signature on the token
        try
        {
            token.VerifySignatureForHash(
                expectedHash, HashAlgorithmName.SHA256,
                out _, extraCandidates: null);
        }
        catch (CryptographicException ex)
        {
            return new TimestampVerificationInfo
            {
                Timestamp = tokenInfo.Timestamp,
                IsValid = false,
                Error = $"Timestamp token signature verification failed: {ex.Message}"
            };
        }

        return new TimestampVerificationInfo
        {
            Timestamp = tokenInfo.Timestamp,
            IsValid = true
        };
    }

    private static TimestampVerificationInfo ValidateTokenInfo(
        Rfc3161TimestampTokenInfo tokenInfo, byte[] signatureValueBytes)
    {
        var expectedHash = SHA256.HashData(signatureValueBytes);

        // Verify the hash algorithm is SHA-256
        if (tokenInfo.HashAlgorithmId.Value != Sha256Oid.Value)
        {
            return new TimestampVerificationInfo
            {
                Timestamp = tokenInfo.Timestamp,
                IsValid = false,
                Error = $"Unsupported timestamp hash algorithm: {tokenInfo.HashAlgorithmId.Value}. Expected SHA-256."
            };
        }

        if (!tokenInfo.GetMessageHash().Span.SequenceEqual(expectedHash))
        {
            return new TimestampVerificationInfo
            {
                Timestamp = tokenInfo.Timestamp,
                IsValid = false,
                Error = "Timestamp token hash does not match signature bytes."
            };
        }

        return new TimestampVerificationInfo
        {
            Timestamp = tokenInfo.Timestamp,
            IsValid = true
        };
    }
}
