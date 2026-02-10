using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests;

public class KeyLoaderTests : IDisposable
{
    private readonly string _tempDir;

    public KeyLoaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-key-test-" + Guid.NewGuid().ToString("N")[..8]);
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
        var result = KeyLoader.Load(
            Path.Combine(_tempDir, "nonexistent.pem"), null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal(KeyLoadErrorKind.FileNotFound, result.ErrorKind);
        Assert.Contains("not found", result.ErrorMessage);
    }

    [Fact]
    public void Load_UnknownAlgorithm_ReturnsError()
    {
        var keyPath = Path.Combine(_tempDir, "key.pem");
        File.WriteAllText(keyPath, "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----");

        var result = KeyLoader.Load(keyPath, null, "unknown-algo");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeyLoadErrorKind.UnknownAlgorithm, result.ErrorKind);
        Assert.Contains("unknown-algo", result.ErrorMessage);
    }

    [Fact]
    public void Load_EncryptedKeyWithoutPassphrase_ReturnsError()
    {
        var prefix = Path.Combine(_tempDir, "enc");
        GenerateEncryptedKey(prefix, "test-pass");

        var result = KeyLoader.Load(prefix + ".pem", null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal(KeyLoadErrorKind.PassphraseRequired, result.ErrorKind);
        Assert.Contains("passphrase", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_EncryptedKeyWrongPassphrase_ReturnsError()
    {
        var prefix = Path.Combine(_tempDir, "enc2");
        GenerateEncryptedKey(prefix, "correct-pass");

        var result = KeyLoader.Load(prefix + ".pem", "wrong-pass", null);

        Assert.False(result.IsSuccess);
        Assert.Equal(KeyLoadErrorKind.CryptoError, result.ErrorKind);
    }

    [Fact]
    public void Load_UnencryptedKey_ReturnsSignerSuccessfully()
    {
        var prefix = Path.Combine(_tempDir, "plain");
        GenerateUnencryptedKey(prefix);

        var result = KeyLoader.Load(prefix + ".pem", null, null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
        Assert.NotEmpty(signer.PublicKey);
    }

    [Fact]
    public void Load_EncryptedKeyWithPassphrase_ReturnsSignerSuccessfully()
    {
        var prefix = Path.Combine(_tempDir, "enc3");
        GenerateEncryptedKey(prefix, "my-pass");

        var result = KeyLoader.Load(prefix + ".pem", "my-pass", null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
    }

    [Fact]
    public void Load_EncryptedKeyWithAlgorithmHint_ReturnsSignerSuccessfully()
    {
        var prefix = Path.Combine(_tempDir, "enc4");
        GenerateEncryptedKey(prefix, "hint-pass");

        var result = KeyLoader.Load(prefix + ".pem", "hint-pass", "ecdsa-p256");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
    }

    [Fact]
    public void Load_PfxExtension_AutoDetectsAsPfx()
    {
        var pfxPath = CreatePfxFile("auto.pfx", "pfx-pass");

        var result = KeyLoader.Load(pfxPath, "pfx-pass", null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(Sigil.Crypto.SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void Load_PfxUppercaseExtension_AutoDetectsAsPfx()
    {
        var pfxPath = CreatePfxFile("auto.PFX", "pfx-pass-upper");

        var result = KeyLoader.Load(pfxPath, "pfx-pass-upper", null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
    }

    [Fact]
    public void Load_P12Extension_AutoDetectsAsPfx()
    {
        var pfxPath = CreatePfxFile("auto.p12", "p12-pass");

        var result = KeyLoader.Load(pfxPath, "p12-pass", null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
    }

    [Fact]
    public void Load_PfxWithoutPassword_Succeeds()
    {
        var pfxPath = CreatePfxFile("nopass.pfx", password: null);

        var result = KeyLoader.Load(pfxPath, null, null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
    }

    [Fact]
    public void Load_PfxWrongPassword_ReturnsError()
    {
        var pfxPath = CreatePfxFile("wrong.pfx", "correct");

        var result = KeyLoader.Load(pfxPath, "wrong", null);

        Assert.False(result.IsSuccess);
        Assert.True(
            result.ErrorKind is KeyLoadErrorKind.PassphraseRequired or KeyLoadErrorKind.CryptoError,
            $"Expected PassphraseRequired or CryptoError, got {result.ErrorKind}");
    }

    [Fact]
    public void Load_PfxFileNotFound_ReturnsError()
    {
        var result = KeyLoader.Load(
            Path.Combine(_tempDir, "missing.pfx"), null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal(KeyLoadErrorKind.FileNotFound, result.ErrorKind);
    }

    private string CreatePfxFile(string fileName, string? password)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }

    private static void GenerateEncryptedKey(string prefix, string passphrase)
    {
        using var signer = Sigil.Crypto.ECDsaP256Signer.Generate();
        var pemBytes = signer.ExportEncryptedPrivateKeyPemBytes(passphrase.AsSpan());
        File.WriteAllBytes(prefix + ".pem", pemBytes);
        File.WriteAllText(prefix + ".pub.pem", signer.ExportPublicKeyPem());
    }

    private static void GenerateUnencryptedKey(string prefix)
    {
        using var signer = Sigil.Crypto.ECDsaP256Signer.Generate();
        var pemBytes = signer.ExportPrivateKeyPemBytes();
        File.WriteAllBytes(prefix + ".pem", pemBytes);
        File.WriteAllText(prefix + ".pub.pem", signer.ExportPublicKeyPem());
    }
}
