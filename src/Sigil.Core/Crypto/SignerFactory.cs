using System.Security.Cryptography;
using System.Text;

namespace Sigil.Crypto;

/// <summary>
/// Factory for creating signers. Supports generation and auto-detection from PEM files.
/// </summary>
public static class SignerFactory
{
    /// <summary>
    /// Generates a new signer with a fresh key pair for the specified algorithm.
    /// </summary>
    public static ISigner Generate(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ECDsaP256 => ECDsaP256Signer.Generate(),
        SigningAlgorithm.ECDsaP384 => ECDsaP384Signer.Generate(),
        SigningAlgorithm.Rsa => RsaSigner.Generate(),
        SigningAlgorithm.Ed25519 => throw new NotSupportedException(
            "Ed25519 is not yet available in this .NET SDK. It will be supported in a future release."),
        SigningAlgorithm.MLDsa65 => MLDsa65Signer.Generate(),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    /// <summary>
    /// Creates a signer from a PEM-encoded private key, auto-detecting the algorithm.
    /// Supports PKCS#8 (BEGIN PRIVATE KEY), encrypted PKCS#8 (BEGIN ENCRYPTED PRIVATE KEY),
    /// SEC1 EC keys (BEGIN EC PRIVATE KEY), and PKCS#1 RSA keys (BEGIN RSA PRIVATE KEY).
    /// </summary>
    public static ISigner CreateFromPem(ReadOnlySpan<char> pem, ReadOnlySpan<char> passphrase = default)
        => CreateFromPem(pem, passphrase, algorithmHint: null);

    /// <summary>
    /// Creates a signer from a PEM-encoded private key with an optional algorithm hint.
    /// When a hint is provided for encrypted PEMs, the factory dispatches directly to the
    /// correct algorithm without trial-and-error, providing clearer error messages.
    /// For unencrypted PEMs, the hint is ignored (OID-based detection is deterministic).
    /// </summary>
    public static ISigner CreateFromPem(
        ReadOnlySpan<char> pem,
        ReadOnlySpan<char> passphrase,
        SigningAlgorithm? algorithmHint)
    {
        if (pem.IsEmpty || pem.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(pem));

        bool isEncrypted = pem.IndexOf("ENCRYPTED".AsSpan()) >= 0;

        if (isEncrypted)
        {
            return algorithmHint.HasValue
                ? CreateFromEncryptedPemWithHint(pem, passphrase, algorithmHint.Value)
                : CreateFromEncryptedPem(pem, passphrase);
        }

        // Unencrypted: ignore hint, use deterministic detection
        if (pem.IndexOf("BEGIN EC PRIVATE KEY".AsSpan()) >= 0)
            return CreateEcSignerFromPem(pem);

        if (pem.IndexOf("BEGIN RSA PRIVATE KEY".AsSpan()) >= 0)
            return RsaSigner.FromPem(pem);

        if (pem.IndexOf("BEGIN PRIVATE KEY".AsSpan()) >= 0)
            return CreateFromPkcs8Pem(pem);

        throw new NotSupportedException("Unrecognized PEM format. Expected a private key PEM.");
    }

    private static ISigner CreateFromPkcs8Pem(ReadOnlySpan<char> pem)
    {
        // Parse the PKCS#8 DER to detect the algorithm OID
        // Import into a temporary key to get the DER bytes
        var pemString = pem.ToString();
        var lines = pemString.Split('\n');
        var base64Builder = new StringBuilder();
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("-----", StringComparison.Ordinal))
                continue;
            base64Builder.Append(trimmed);
        }

        var derBytes = Convert.FromBase64String(base64Builder.ToString());
        var algorithm = AlgorithmDetector.DetectFromPkcs8Der(derBytes);

        return algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => ECDsaP256Signer.FromPem(pem),
            SigningAlgorithm.ECDsaP384 => ECDsaP384Signer.FromPem(pem),
            SigningAlgorithm.Rsa => RsaSigner.FromPem(pem),
            SigningAlgorithm.Ed25519 => throw new NotSupportedException(
                "Ed25519 is not yet available in this .NET SDK."),
            SigningAlgorithm.MLDsa65 => MLDsa65Signer.FromPem(pem),
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithm}")
        };
    }

    private static ISigner CreateEcSignerFromPem(ReadOnlySpan<char> pem)
    {
        // SEC1 format — import to detect curve
        using var tempKey = ECDsa.Create();
        tempKey.ImportFromPem(pem);
        var parameters = tempKey.ExportParameters(false);
        var curveName = parameters.Curve.Oid?.FriendlyName;

        // Re-import into the correct signer type
        return curveName switch
        {
            "ECDSA_P256" or "nistP256" => ECDsaP256Signer.FromPem(pem),
            "ECDSA_P384" or "nistP384" => ECDsaP384Signer.FromPem(pem),
            _ => throw new NotSupportedException($"Unsupported EC curve: {curveName}")
        };
    }

    private static ISigner CreateFromEncryptedPemWithHint(
        ReadOnlySpan<char> pem,
        ReadOnlySpan<char> passphrase,
        SigningAlgorithm algorithm)
    {
        if (passphrase.IsEmpty || passphrase.IsWhiteSpace())
            throw new ArgumentException("Passphrase required for encrypted PEM.", nameof(passphrase));

        return algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => ECDsaP256Signer.FromEncryptedPem(pem, passphrase),
            SigningAlgorithm.ECDsaP384 => ECDsaP384Signer.FromEncryptedPem(pem, passphrase),
            SigningAlgorithm.Rsa => RsaSigner.FromEncryptedPem(pem, passphrase),
            SigningAlgorithm.Ed25519 => throw new NotSupportedException(
                "Ed25519 is not yet available in this .NET SDK."),
            SigningAlgorithm.MLDsa65 => MLDsa65Signer.FromEncryptedPem(pem, passphrase),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }

    private static ISigner CreateFromEncryptedPem(ReadOnlySpan<char> pem, ReadOnlySpan<char> passphrase)
    {
        if (passphrase.IsEmpty || passphrase.IsWhiteSpace())
            throw new ArgumentException("Passphrase required for encrypted PEM.", nameof(passphrase));

        // Encrypted PKCS#8 — can't parse OID without decrypting.
        // Try ECDsa first (most common), then RSA, then ML-DSA-65.
        // Collect exceptions to distinguish wrong passphrase from unsupported algorithm.
        // Note: Successful probe requires re-import (double PBKDF2). Use algorithm hint to avoid.
        var exceptions = new List<Exception>(3);

        try
        {
            using var ecKey = ECDsa.Create();
            ecKey.ImportFromEncryptedPem(pem, passphrase);
            var parameters = ecKey.ExportParameters(false);
            var curveName = parameters.Curve.Oid?.FriendlyName;

            return curveName switch
            {
                "ECDSA_P256" or "nistP256" => ECDsaP256Signer.FromEncryptedPem(pem, passphrase),
                "ECDSA_P384" or "nistP384" => ECDsaP384Signer.FromEncryptedPem(pem, passphrase),
                _ => throw new NotSupportedException($"Unsupported EC curve: {curveName}")
            };
        }
        catch (CryptographicException ex)
        {
            exceptions.Add(ex);
        }

        try
        {
            return RsaSigner.FromEncryptedPem(pem, passphrase);
        }
        catch (CryptographicException ex)
        {
            exceptions.Add(ex);
        }

        try
        {
            return MLDsa65Signer.FromEncryptedPem(pem, passphrase);
        }
        catch (CryptographicException ex)
        {
            exceptions.Add(ex);
        }
        catch (PlatformNotSupportedException ex)
        {
            exceptions.Add(ex);
        }

        // If all CryptographicExceptions have the same message, it's a passphrase issue —
        // PBES2 decryption fails identically regardless of target algorithm.
        var cryptoExceptions = exceptions.OfType<CryptographicException>().ToList();
        if (cryptoExceptions.Count >= 2 &&
            cryptoExceptions.All(e => e.Message == cryptoExceptions[0].Message))
        {
            throw new CryptographicException(
                "Could not decrypt the private key. Verify the passphrase is correct.",
                cryptoExceptions[0]);
        }

        throw new NotSupportedException(
            "Could not detect algorithm from encrypted PEM. Supported: ECDSA P-256, P-384, RSA, ML-DSA-65.");
    }
}
