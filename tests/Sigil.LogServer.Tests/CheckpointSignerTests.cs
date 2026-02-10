using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.Webpki.JsonCanonicalizer;
using Xunit;

namespace Sigil.LogServer.Tests;

public sealed class CheckpointSignerTests : IDisposable
{
    private readonly string _tempDir;

    public CheckpointSignerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-ckpt-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }
    [Fact]
    public void Generate_CreatesValidSignerWithEcdsaP256Key()
    {
        // Act
        using var signer = CheckpointSigner.Generate();

        // Assert
        Assert.NotNull(signer);
        Assert.NotNull(signer.PublicKeySpki);
        Assert.True(signer.PublicKeySpki.Length > 0);
    }

    [Fact]
    public void PublicKeySpki_IsValidSpki_CanImportIntoECDsa()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();

        // Act
        using var ecdsa = ECDsa.Create();
        var spki = signer.PublicKeySpki;

        // Assert
        var exception = Record.Exception(() => ecdsa.ImportSubjectPublicKeyInfo(spki, out _));
        Assert.Null(exception);
    }

    [Fact]
    public void PublicKeyBase64_IsValidBase64OfPublicKeySpki()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();

        // Act
        var base64 = signer.PublicKeyBase64;
        var decoded = Convert.FromBase64String(base64);

        // Assert
        Assert.Equal(signer.PublicKeySpki, decoded);
    }

    [Fact]
    public void SignCheckpoint_ProducesBase64DecodableOutput()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();
        var treeSize = 42L;
        var rootHash = "abc123";
        var timestamp = "2026-02-10T12:00:00Z";

        // Act
        var signed = signer.SignCheckpoint(treeSize, rootHash, timestamp);

        // Assert
        var exception = Record.Exception(() => Convert.FromBase64String(signed));
        Assert.Null(exception);
    }

    [Fact]
    public void SignCheckpoint_OutputContainsJsonPayloadAndSignatureSeparatedByDot()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();
        var treeSize = 100L;
        var rootHash = "hash123";
        var timestamp = "2026-02-10T12:30:00Z";

        // Act
        var signed = signer.SignCheckpoint(treeSize, rootHash, timestamp);
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(signed));

        // Assert
        Assert.Contains(".", decoded);
        var parts = decoded.Split('.');
        Assert.Equal(2, parts.Length);

        // First part should be valid JSON
        var exception = Record.Exception(() => new JsonCanonicalizer(parts[0]));
        Assert.Null(exception);

        // Second part should be valid base64
        var signatureException = Record.Exception(() => Convert.FromBase64String(parts[1]));
        Assert.Null(signatureException);
    }

    [Fact]
    public void SignCheckpoint_IsVerifiable_UsingECDsaSignature()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();
        var treeSize = 200L;
        var rootHash = "rootHashValue";
        var timestamp = "2026-02-10T13:00:00Z";

        // Act
        var signed = signer.SignCheckpoint(treeSize, rootHash, timestamp);

        // Decode outer base64
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(signed));
        var parts = decoded.Split('.');
        var jsonPayload = parts[0];
        var signatureBase64 = parts[1];

        // JCS-canonicalize the payload
        var canonical = new JsonCanonicalizer(jsonPayload).GetEncodedUTF8();

        // Decode signature
        var signature = Convert.FromBase64String(signatureBase64);

        // Import public key and verify
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(signer.PublicKeySpki, out _);

        // Assert
        var isValid = ecdsa.VerifyData(canonical, signature, HashAlgorithmName.SHA256);
        Assert.True(isValid);
    }

    [Fact]
    public void FromPfx_LoadsEcdsaKeyAndSigns()
    {
        var pfxPath = CreateEcdsaPfx("ckpt.pfx", "ckpt-pass");

        using var signer = CheckpointSigner.FromPfx(pfxPath, "ckpt-pass");

        Assert.NotEmpty(signer.PublicKeySpki);
        var signed = signer.SignCheckpoint(1L, "hash", "2026-02-10T14:00:00Z");
        Assert.NotEmpty(signed);
    }

    [Fact]
    public void FromPfx_SignedCheckpoint_IsVerifiable()
    {
        var pfxPath = CreateEcdsaPfx("verify.pfx", "verify-pass");

        using var signer = CheckpointSigner.FromPfx(pfxPath, "verify-pass");
        var signed = signer.SignCheckpoint(50L, "testHash", "2026-02-10T15:00:00Z");

        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(signed));
        var parts = decoded.Split('.');
        var canonical = new JsonCanonicalizer(parts[0]).GetEncodedUTF8();
        var signature = Convert.FromBase64String(parts[1]);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(signer.PublicKeySpki, out _);
        Assert.True(ecdsa.VerifyData(canonical, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void FromPfx_WrongPassword_ThrowsCryptographicException()
    {
        var pfxPath = CreateEcdsaPfx("wrongpass.pfx", "correct");

        Assert.ThrowsAny<CryptographicException>(
            () => CheckpointSigner.FromPfx(pfxPath, "wrong"));
    }

    [Fact]
    public void FromPfx_NonEcdsaKey_ThrowsArgumentException()
    {
        var pfxPath = CreateRsaPfx("rsa.pfx", "rsa-pass");

        Assert.Throws<ArgumentException>(
            () => CheckpointSigner.FromPfx(pfxPath, "rsa-pass"));
    }

    private string CreateEcdsaPfx(string fileName, string password)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=CkptTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }

    private string CreateRsaPfx(string fileName, string password)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=RsaCkpt", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }
}
