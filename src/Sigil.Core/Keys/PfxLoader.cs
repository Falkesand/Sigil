using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Crypto;

namespace Sigil.Keys;

/// <summary>
/// Loads a signer from a PFX/PKCS#12 file with secure memory handling.
/// Extracts the private key as PKCS#8 DER and delegates to SignerFactory.
/// </summary>
public static class PfxLoader
{
    public static PfxLoadResult<ISigner> Load(string pfxPath, string? password)
    {
        ArgumentNullException.ThrowIfNull(pfxPath);

        if (!File.Exists(pfxPath))
            return PfxLoadResult<ISigner>.Fail(
                PfxLoadErrorKind.FileNotFound, $"PFX file not found: {pfxPath}");

        byte[] pfxBytes = File.ReadAllBytes(pfxPath);
        try
        {
            return LoadFromBytes(pfxBytes, password);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfxBytes);
        }
    }

    public static PfxLoadResult<ISigner> LoadFromBytes(byte[] pfxBytes, string? password)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);

        X509Certificate2 cert;
        try
        {
            cert = X509CertificateLoader.LoadPkcs12(
                pfxBytes, password, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        }
        catch (CryptographicException ex) when (ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("MAC", StringComparison.OrdinalIgnoreCase))
        {
            return PfxLoadResult<ISigner>.Fail(
                PfxLoadErrorKind.PasswordRequired,
                "Failed to open PFX: incorrect or missing password.");
        }
        catch (CryptographicException ex)
        {
            return PfxLoadResult<ISigner>.Fail(
                PfxLoadErrorKind.InvalidFormat,
                $"Failed to load PFX: {ex.Message}");
        }

        try
        {
            if (!cert.HasPrivateKey)
            {
                return PfxLoadResult<ISigner>.Fail(
                    PfxLoadErrorKind.NoPrivateKey,
                    "PFX does not contain a private key.");
            }

            return TryExtractSigner(cert);
        }
        finally
        {
            cert.Dispose();
        }
    }

    private static PfxLoadResult<ISigner> TryExtractSigner(X509Certificate2 cert)
    {
        // Try ECDsa
        var ecKey = cert.GetECDsaPrivateKey();
        if (ecKey is not null)
            return TryImportAsymmetricKey(ecKey);

        // Try RSA
        var rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey is not null)
            return TryImportAsymmetricKey(rsaKey);

        return PfxLoadResult<ISigner>.Fail(
            PfxLoadErrorKind.UnsupportedAlgorithm,
            "PFX private key algorithm is not supported. Supported: ECDSA (P-256, P-384, P-521), RSA.");
    }

    private static PfxLoadResult<ISigner> TryImportAsymmetricKey(AsymmetricAlgorithm key)
    {
        byte[] pkcs8Der;
        try
        {
            pkcs8Der = key.ExportPkcs8PrivateKey();
        }
        catch (CryptographicException)
        {
            return PfxLoadResult<ISigner>.Fail(
                PfxLoadErrorKind.NonExportableKey,
                "PFX private key is marked as non-exportable. Use --cert-store for non-exportable keys.");
        }

        try
        {
            var signer = SignerFactory.CreateFromPkcs8Der(pkcs8Der);
            return PfxLoadResult<ISigner>.Ok(signer);
        }
        catch (NotSupportedException ex)
        {
            return PfxLoadResult<ISigner>.Fail(
                PfxLoadErrorKind.UnsupportedAlgorithm, ex.Message);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8Der);
        }
    }
}
