using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class CertificateLoaderTests : IDisposable
{
    private readonly string _tempDir;

    public CertificateLoaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-certloader-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void LoadFromPfx_ValidPfx_ReturnsCertWithPrivateKey()
    {
        using var cert = PeCertHelper.CreateSelfSignedEcdsaCert();
        var pfxPath = PeCertHelper.ExportToPfx(cert, _tempDir);

        var result = CertificateLoader.LoadFromPfx(pfxPath, "test");

        Assert.True(result.IsSuccess);
        using var loaded = result.Value;
        Assert.True(loaded.HasPrivateKey);
        Assert.Contains("SigilTestEC", loaded.Subject);
    }

    [Fact]
    public void LoadFromPfx_WrongPassword_ReturnsFail()
    {
        using var cert = PeCertHelper.CreateSelfSignedRsaCert();
        var pfxPath = PeCertHelper.ExportToPfx(cert, _tempDir, "correct");

        var result = CertificateLoader.LoadFromPfx(pfxPath, "wrong");

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.SigningFailed, result.ErrorKind);
    }

    [Fact]
    public void LoadFromPfx_FileNotFound_ReturnsFail()
    {
        var result = CertificateLoader.LoadFromPfx(
            Path.Combine(_tempDir, "nonexistent.pfx"), null);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.SigningFailed, result.ErrorKind);
        Assert.Contains("not found", result.ErrorMessage);
    }

    [Fact]
    public void LoadFromPfx_NoCertWithPublicKeyOnly_ReturnsFail()
    {
        // Create a PFX with only a certificate (no private key)
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=NoPK", ecdsa, HashAlgorithmName.SHA256);
        using var certWithPk = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        // Export just the public cert (DER), then re-wrap as PFX without private key
        var derBytes = certWithPk.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
        using var pubOnly = X509CertificateLoader.LoadCertificate(derBytes);
        var pfxBytes = pubOnly.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "test");
        var pfxPath = Path.Combine(_tempDir, "pubonly.pfx");
        File.WriteAllBytes(pfxPath, pfxBytes);

        var result = CertificateLoader.LoadFromPfx(pfxPath, "test");

        Assert.False(result.IsSuccess);
        Assert.Contains("private key", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
