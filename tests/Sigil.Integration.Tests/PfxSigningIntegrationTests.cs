using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Cli.Commands;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Integration.Tests;

public class PfxSigningIntegrationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public PfxSigningIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-pfx-integ-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.bin");
        File.WriteAllBytes(_artifactPath, RandomNumberGenerator.GetBytes(1024));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void PfxLoader_Sign_Verify_RoundTrip_P256()
    {
        var pfxPath = CreateEcdsaPfx("p256.pfx", "pass", ECCurve.NamedCurves.nistP256);

        var loadResult = PfxLoader.Load(pfxPath, "pass");
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);
        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void PfxLoader_Sign_Verify_RoundTrip_RSA()
    {
        var pfxPath = CreateRsaPfx("rsa.pfx", "rsa-pass");

        var loadResult = PfxLoader.Load(pfxPath, "rsa-pass");
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);
        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("rsa-pss-sha256", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void KeyLoader_AutoDetects_PFX_Sign_Verify()
    {
        var pfxPath = CreateEcdsaPfx("autodetect.pfx", "auto-pass", ECCurve.NamedCurves.nistP256);

        var loadResult = KeyLoader.Load(pfxPath, "auto-pass", null);
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);
        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void KeyLoader_P12Extension_AutoDetects_As_PFX()
    {
        var pfxPath = CreateEcdsaPfx("autodetect.p12", "p12-pass", ECCurve.NamedCurves.nistP256);

        var loadResult = KeyLoader.Load(pfxPath, "p12-pass", null);
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void PFX_Manifest_Sign_Verify_RoundTrip()
    {
        var file1 = CreateFile("src/main.cs", "class Program {}");
        var file2 = CreateFile("src/util.cs", "class Util {}");

        var pfxPath = CreateEcdsaPfx("manifest.pfx", "manifest-pass", ECCurve.NamedCurves.nistP384);

        var loadResult = PfxLoader.Load(pfxPath, "manifest-pass");
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer, fp, "pfx-build");
        var json = ManifestSigner.Serialize(envelope);
        var deserialized = ManifestSigner.Deserialize(json);

        var result = ManifestValidator.Verify(_tempDir, deserialized);
        Assert.True(result.AllDigestsMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ecdsa-p384", deserialized.Signatures[0].Algorithm);
    }

    [Fact]
    public void CertificateKeySigner_Sign_Verify_RoundTrip()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=IntegTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        using var certSigner = CertificateKeySigner.Create(cert);
        var fp = KeyFingerprint.Compute(certSigner.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, certSigner, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);
        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void PFX_P521_Sign_Verify_RoundTrip()
    {
        var pfxPath = CreateEcdsaPfx("p521.pfx", "p521-pass", ECCurve.NamedCurves.nistP521);

        var loadResult = PfxLoader.Load(pfxPath, "p521-pass");
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);
        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ecdsa-p521", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void PFX_Without_Password_Sign_Verify()
    {
        var pfxPath = CreateEcdsaPfx("nopass.pfx", null, ECCurve.NamedCurves.nistP256);

        var loadResult = PfxLoader.Load(pfxPath, null);
        Assert.True(loadResult.IsSuccess);

        using var signer = loadResult.Value;
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var result = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
    }

    private string CreateFile(string relativePath, string content)
    {
        var fullPath = Path.Combine(_tempDir, relativePath.Replace('/', Path.DirectorySeparatorChar));
        var dir = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(fullPath, content);
        return fullPath;
    }

    private string CreateEcdsaPfx(string fileName, string? password, ECCurve curve)
    {
        using var ecdsa = ECDsa.Create(curve);
        var req = new CertificateRequest("CN=IntegTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }

    private string CreateRsaPfx(string fileName, string password)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=RsaInteg", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }
}
