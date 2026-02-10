using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Core.Tests.Keys;

public sealed class PfxLoaderTests : IDisposable
{
    private readonly string _tempDir;

    public PfxLoaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-pfx-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Load_FileNotFound_ReturnsError()
    {
        var result = PfxLoader.Load(Path.Combine(_tempDir, "nonexistent.pfx"), null);

        Assert.False(result.IsSuccess);
        Assert.Equal(PfxLoadErrorKind.FileNotFound, result.ErrorKind);
    }

    [Fact]
    public void Load_ValidEcdsaP256Pfx_ReturnsSignerWithCorrectAlgorithm()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP256, "test.pfx", "test-pass");

        var result = PfxLoader.Load(pfxPath, "test-pass");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void Load_ValidRsaPfx_ReturnsSignerWithCorrectAlgorithm()
    {
        var pfxPath = CreateRsaPfxFile("rsa.pfx", "rsa-pass");

        var result = PfxLoader.Load(pfxPath, "rsa-pass");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.Rsa, signer.Algorithm);
    }

    [Fact]
    public void Load_PasswordProtectedPfx_WrongPassword_ReturnsError()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP256, "enc.pfx", "correct-pass");

        var result = PfxLoader.Load(pfxPath, "wrong-pass");

        Assert.False(result.IsSuccess);
        // Different OSes may report different error kinds for wrong password
        Assert.True(
            result.ErrorKind is PfxLoadErrorKind.PasswordRequired or PfxLoadErrorKind.InvalidFormat,
            $"Expected PasswordRequired or InvalidFormat, got {result.ErrorKind}");
    }

    [Fact]
    public void Load_PasswordProtectedPfx_NullPassword_ReturnsError()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP256, "enc2.pfx", "my-pass");

        var result = PfxLoader.Load(pfxPath, null);

        Assert.False(result.IsSuccess);
        Assert.True(
            result.ErrorKind is PfxLoadErrorKind.PasswordRequired or PfxLoadErrorKind.InvalidFormat,
            $"Expected PasswordRequired or InvalidFormat, got {result.ErrorKind}");
    }

    [Fact]
    public void Load_PfxWithoutPrivateKey_ReturnsError()
    {
        // Create a PFX containing only the public certificate
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=NoPK", ecdsa, HashAlgorithmName.SHA256);
        using var certWithKey = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        // Export only the public certificate, then create a PFX from it
        var certBytes = certWithKey.Export(X509ContentType.Cert);
        using var certPublicOnly = X509CertificateLoader.LoadCertificate(certBytes);
        var pfxBytes = certPublicOnly.Export(X509ContentType.Pfx, "");
        var pfxPath = Path.Combine(_tempDir, "nopk.pfx");
        File.WriteAllBytes(pfxPath, pfxBytes);

        var result = PfxLoader.Load(pfxPath, "");

        Assert.False(result.IsSuccess);
        Assert.Equal(PfxLoadErrorKind.NoPrivateKey, result.ErrorKind);
    }

    [Fact]
    public void Load_ValidEcdsaP384Pfx_ReturnsCorrectAlgorithm()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP384, "p384.pfx", "pass384");

        var result = PfxLoader.Load(pfxPath, "pass384");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP384, signer.Algorithm);
    }

    [Fact]
    public void Load_ValidEcdsaP521Pfx_ReturnsCorrectAlgorithm()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP521, "p521.pfx", "pass521");

        var result = PfxLoader.Load(pfxPath, "pass521");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP521, signer.Algorithm);
    }

    [Fact]
    public void Load_SignAndVerify_RoundTrip()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP256, "rt.pfx", "rt-pass");
        var data = Encoding.UTF8.GetBytes("pfx-roundtrip-test");

        var result = PfxLoader.Load(pfxPath, "rt-pass");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            signer.PublicKey, signer.Algorithm.ToCanonicalName());
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Load_UnprotectedPfx_NullPassword_Succeeds()
    {
        var pfxPath = CreatePfxFile(ECCurve.NamedCurves.nistP256, "unprotected.pfx", password: null);

        var result = PfxLoader.Load(pfxPath, null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void LoadFromBytes_ValidPfx_Succeeds()
    {
        var pfxBytes = CreatePfxBytes(ECCurve.NamedCurves.nistP256, "byte-pass");

        var result = PfxLoader.LoadFromBytes(pfxBytes, "byte-pass");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    private string CreatePfxFile(ECCurve curve, string fileName, string? password)
    {
        var pfxBytes = CreatePfxBytes(curve, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }

    private static byte[] CreatePfxBytes(ECCurve curve, string? password)
    {
        using var ecdsa = ECDsa.Create(curve);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        return cert.Export(X509ContentType.Pfx, password);
    }

    private string CreateRsaPfxFile(string fileName, string password)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }
}
