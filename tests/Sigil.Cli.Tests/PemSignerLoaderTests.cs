using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests;

public class PemSignerLoaderTests : IDisposable
{
    private readonly string _tempDir;

    public PemSignerLoaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-pem-test-" + Guid.NewGuid().ToString("N")[..8]);
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
        var result = PemSignerLoader.Load(
            Path.Combine(_tempDir, "nonexistent.pem"), null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal(PemLoadErrorKind.FileNotFound, result.ErrorKind);
        Assert.Contains("not found", result.ErrorMessage);
    }

    [Fact]
    public void Load_UnknownAlgorithm_ReturnsError()
    {
        // Create a dummy PEM file so it passes the file-exists check
        var keyPath = Path.Combine(_tempDir, "key.pem");
        File.WriteAllText(keyPath, "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----");

        var result = PemSignerLoader.Load(keyPath, null, "unknown-algo");

        Assert.False(result.IsSuccess);
        Assert.Equal(PemLoadErrorKind.UnknownAlgorithm, result.ErrorKind);
        Assert.Contains("unknown-algo", result.ErrorMessage);
    }

    [Fact]
    public void Load_EncryptedKeyWithoutPassphrase_ReturnsError()
    {
        // Generate a real encrypted key
        var prefix = Path.Combine(_tempDir, "enc");
        GenerateEncryptedKey(prefix, "test-pass");

        var result = PemSignerLoader.Load(prefix + ".pem", null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal(PemLoadErrorKind.PassphraseRequired, result.ErrorKind);
        Assert.Contains("passphrase", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_EncryptedKeyWrongPassphrase_ReturnsError()
    {
        var prefix = Path.Combine(_tempDir, "enc2");
        GenerateEncryptedKey(prefix, "correct-pass");

        var result = PemSignerLoader.Load(prefix + ".pem", "wrong-pass", null);

        Assert.False(result.IsSuccess);
        Assert.Equal(PemLoadErrorKind.CryptoError, result.ErrorKind);
        Assert.Contains("passphrase", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_UnencryptedKey_ReturnsSignerSuccessfully()
    {
        var prefix = Path.Combine(_tempDir, "plain");
        GenerateUnencryptedKey(prefix);

        var result = PemSignerLoader.Load(prefix + ".pem", null, null);

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

        var result = PemSignerLoader.Load(prefix + ".pem", "my-pass", null);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
    }

    [Fact]
    public void Load_EncryptedKeyWithAlgorithmHint_ReturnsSignerSuccessfully()
    {
        var prefix = Path.Combine(_tempDir, "enc4");
        GenerateEncryptedKey(prefix, "hint-pass");

        var result = PemSignerLoader.Load(prefix + ".pem", "hint-pass", "ecdsa-p256");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.NotNull(signer);
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
