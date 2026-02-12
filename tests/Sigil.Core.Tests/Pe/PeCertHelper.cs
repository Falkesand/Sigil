using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigil.Core.Tests.Pe;

/// <summary>
/// Creates self-signed test certificates for Authenticode testing.
/// </summary>
internal static class PeCertHelper
{
    /// <summary>
    /// Creates a self-signed RSA certificate with private key.
    /// The returned certificate can be used for Authenticode signing.
    /// </summary>
    public static X509Certificate2 CreateSelfSignedRsaCert(string subject = "CN=SigilTest")
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subject,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        // Export and re-import to get an ephemeral key-bearing cert
        var pfxBytes = cert.Export(X509ContentType.Pfx, "test");
        var loaded = X509CertificateLoader.LoadPkcs12(
            pfxBytes, "test",
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        CryptographicOperations.ZeroMemory(pfxBytes);
        return loaded;
    }

    /// <summary>
    /// Creates a self-signed ECDSA P-256 certificate with private key.
    /// </summary>
    public static X509Certificate2 CreateSelfSignedEcdsaCert(string subject = "CN=SigilTestEC")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            subject,
            ecdsa,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        var pfxBytes = cert.Export(X509ContentType.Pfx, "test");
        var loaded = X509CertificateLoader.LoadPkcs12(
            pfxBytes, "test",
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        CryptographicOperations.ZeroMemory(pfxBytes);
        return loaded;
    }

    /// <summary>
    /// Exports a certificate to a PFX file on disk. Returns the file path.
    /// </summary>
    public static string ExportToPfx(X509Certificate2 cert, string directory, string password = "test")
    {
        var pfxPath = Path.Combine(directory, "test.pfx");
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        try
        {
            File.WriteAllBytes(pfxPath, pfxBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfxBytes);
        }
        return pfxPath;
    }
}
