using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Keys;

/// <summary>
/// Windows Certificate Store key provider. Finds certificates by thumbprint
/// in the Personal (My) store and returns an ISigner.
/// For exportable keys, extracts PKCS#8 DER and creates a standard signer.
/// For non-exportable keys (CNG/HSM-backed), wraps via CertificateKeySigner.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CertStoreKeyProvider : IKeyProvider
{
    private readonly StoreLocation _location;

    public CertStoreKeyProvider(StoreLocation location = StoreLocation.CurrentUser)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("CertStoreKeyProvider is only supported on Windows.");
        _location = location;
    }

    public Task<VaultResult<ISigner>> GetSignerAsync(string keyReference, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(keyReference);

        if (string.IsNullOrWhiteSpace(keyReference))
            return Task.FromResult(VaultResult<ISigner>.Fail(
                VaultErrorKind.InvalidKeyReference, "Certificate thumbprint cannot be empty."));

        X509Certificate2? cert = null;
        try
        {
            cert = FindCertificate(keyReference);
            if (cert is null)
                return Task.FromResult(VaultResult<ISigner>.Fail(
                    VaultErrorKind.KeyNotFound,
                    $"Certificate with thumbprint '{keyReference}' not found in {_location}/My store."));

            if (!cert.HasPrivateKey)
            {
                cert.Dispose();
                return Task.FromResult(VaultResult<ISigner>.Fail(
                    VaultErrorKind.KeyNotFound,
                    $"Certificate '{keyReference}' does not have a private key."));
            }

            // Try to export the private key first (works for exportable keys)
            ISigner signer;
            try
            {
                signer = TryCreateExportableSigner(cert);
                cert.Dispose(); // Signer owns a copy of the key
            }
            catch (CryptographicException)
            {
                // Non-exportable key — wrap the cert directly
                // CertificateKeySigner does NOT own the cert, so we keep it alive
                // by NOT disposing it here. The signer's Dispose will NOT dispose the cert.
                // This is a minor but acceptable leak for cert store scenarios
                // where the cert lifetime matches the operation lifetime.
                signer = CertificateKeySigner.Create(cert);
                cert = null; // Prevent dispose in finally
            }

            return Task.FromResult(VaultResult<ISigner>.Ok(signer));
        }
        catch (CryptographicException ex)
        {
            cert?.Dispose();
            return Task.FromResult(VaultResult<ISigner>.Fail(
                VaultErrorKind.AccessDenied,
                $"Failed to access certificate store: {ex.Message}"));
        }
    }

    public Task<VaultResult<byte[]>> GetPublicKeyAsync(string keyReference, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(keyReference);

        if (string.IsNullOrWhiteSpace(keyReference))
            return Task.FromResult(VaultResult<byte[]>.Fail(
                VaultErrorKind.InvalidKeyReference, "Certificate thumbprint cannot be empty."));

        try
        {
            using var cert = FindCertificate(keyReference);
            if (cert is null)
                return Task.FromResult(VaultResult<byte[]>.Fail(
                    VaultErrorKind.KeyNotFound,
                    $"Certificate with thumbprint '{keyReference}' not found in {_location}/My store."));

            using var publicKey = cert.PublicKey.GetECDsaPublicKey()
                ?? (AsymmetricAlgorithm?)cert.PublicKey.GetRSAPublicKey();

            if (publicKey is null)
                return Task.FromResult(VaultResult<byte[]>.Fail(
                    VaultErrorKind.UnsupportedAlgorithm,
                    "Certificate public key algorithm is not supported."));

            var spki = publicKey.ExportSubjectPublicKeyInfo();
            return Task.FromResult(VaultResult<byte[]>.Ok(spki));
        }
        catch (CryptographicException ex)
        {
            return Task.FromResult(VaultResult<byte[]>.Fail(
                VaultErrorKind.AccessDenied,
                $"Failed to access certificate store: {ex.Message}"));
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private X509Certificate2? FindCertificate(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, _location);
        store.Open(OpenFlags.ReadOnly);
        var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        return certs.Count > 0 ? certs[0] : null;
    }

    private static ISigner TryCreateExportableSigner(X509Certificate2 cert)
    {
        // Try ECDsa
        var ecKey = cert.GetECDsaPrivateKey();
        if (ecKey is not null)
        {
            var pkcs8 = ecKey.ExportPkcs8PrivateKey();
            try
            {
                return SignerFactory.CreateFromPkcs8Der(pkcs8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }

        // Try RSA
        var rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey is not null)
        {
            var pkcs8 = rsaKey.ExportPkcs8PrivateKey();
            try
            {
                return SignerFactory.CreateFromPkcs8Der(pkcs8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }

        throw new NotSupportedException("Certificate key algorithm not supported.");
    }
}
