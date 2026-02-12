using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigil.Pe;

/// <summary>
/// Loads X.509 certificates for Authenticode signing from PFX files or the Windows Certificate Store.
/// Authenticode requires certificates (not bare PEM keys).
/// </summary>
public static class CertificateLoader
{
    public static AuthenticodeResult<X509Certificate2> LoadFromPfx(string path, string? password)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (!File.Exists(path))
            return AuthenticodeResult<X509Certificate2>.Fail(
                AuthenticodeErrorKind.SigningFailed, $"PFX file not found: {path}");

        byte[] pfxBytes = File.ReadAllBytes(path);
        try
        {
            X509Certificate2 cert;
            try
            {
                cert = X509CertificateLoader.LoadPkcs12(
                    pfxBytes, password,
                    X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (CryptographicException ex) when (
                ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("MAC", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticodeResult<X509Certificate2>.Fail(
                    AuthenticodeErrorKind.SigningFailed,
                    "Failed to open PFX: incorrect or missing password.");
            }
            catch (CryptographicException ex)
            {
                return AuthenticodeResult<X509Certificate2>.Fail(
                    AuthenticodeErrorKind.SigningFailed,
                    $"Failed to load PFX: {ex.Message}");
            }

            if (!cert.HasPrivateKey)
            {
                cert.Dispose();
                return AuthenticodeResult<X509Certificate2>.Fail(
                    AuthenticodeErrorKind.SigningFailed,
                    "PFX does not contain a private key. Authenticode requires a certificate with a private key.");
            }

            return AuthenticodeResult<X509Certificate2>.Ok(cert);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfxBytes);
        }
    }

    [SupportedOSPlatform("windows")]
    public static AuthenticodeResult<X509Certificate2> LoadFromCertStore(
        string thumbprint, StoreLocation location)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);

        try
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

            if (certs.Count == 0)
                return AuthenticodeResult<X509Certificate2>.Fail(
                    AuthenticodeErrorKind.SigningFailed,
                    $"Certificate with thumbprint '{thumbprint}' not found in {location}/My store.");

            var cert = certs[0];
            if (!cert.HasPrivateKey)
            {
                cert.Dispose();
                return AuthenticodeResult<X509Certificate2>.Fail(
                    AuthenticodeErrorKind.SigningFailed,
                    $"Certificate '{thumbprint}' does not have a private key.");
            }

            return AuthenticodeResult<X509Certificate2>.Ok(cert);
        }
        catch (CryptographicException ex)
        {
            return AuthenticodeResult<X509Certificate2>.Fail(
                AuthenticodeErrorKind.SigningFailed,
                $"Failed to access certificate store: {ex.Message}");
        }
    }
}
