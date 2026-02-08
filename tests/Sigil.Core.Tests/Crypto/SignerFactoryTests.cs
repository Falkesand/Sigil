#pragma warning disable SYSLIB5006

using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;

namespace Sigil.Core.Tests.Crypto;

public class SignerFactoryTests
{
    [Fact]
    public void Generate_ECDsaP256_ReturnsCorrectAlgorithm()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void Generate_ECDsaP384_ReturnsCorrectAlgorithm()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        Assert.Equal(SigningAlgorithm.ECDsaP384, signer.Algorithm);
    }

    [Fact]
    public void Generate_Rsa_ReturnsCorrectAlgorithm()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.Rsa);
        Assert.Equal(SigningAlgorithm.Rsa, signer.Algorithm);
    }

    [Fact]
    public void Generate_Ed25519_ThrowsNotSupportedException()
    {
        Assert.Throws<NotSupportedException>(() => SignerFactory.Generate(SigningAlgorithm.Ed25519));
    }

    [Fact]
    public void CreateFromPem_ECDsaP256_AutoDetects()
    {
        using var original = ECDsaP256Signer.Generate();
        var pem = original.ExportPrivateKeyPem();

        using var restored = SignerFactory.CreateFromPem(pem.AsSpan());

        Assert.Equal(SigningAlgorithm.ECDsaP256, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_ECDsaP384_AutoDetects()
    {
        using var original = ECDsaP384Signer.Generate();
        var pem = original.ExportPrivateKeyPem();

        using var restored = SignerFactory.CreateFromPem(pem.AsSpan());

        Assert.Equal(SigningAlgorithm.ECDsaP384, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_Rsa_AutoDetects()
    {
        using var original = RsaSigner.Generate();
        var pem = original.ExportPrivateKeyPem();

        using var restored = SignerFactory.CreateFromPem(pem.AsSpan());

        Assert.Equal(SigningAlgorithm.Rsa, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_ECDsaP256_SignAndVerify_RoundTrip()
    {
        using var original = ECDsaP256Signer.Generate();
        var pem = original.ExportPrivateKeyPem();
        var data = Encoding.UTF8.GetBytes("factory round trip");

        using var restored = SignerFactory.CreateFromPem(pem.AsSpan());
        var signature = restored.Sign(data);

        using var verifier = ECDsaP256Verifier.FromPublicKey(original.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void CreateFromPem_EncryptedECDsa_AutoDetects()
    {
        using var original = ECDsaP256Signer.Generate();
        var passphrase = "test-password-456";
        var encryptedPem = original.ExportEncryptedPrivateKeyPem(passphrase);

        using var restored = SignerFactory.CreateFromPem(encryptedPem.AsSpan(), passphrase.AsSpan());

        Assert.Equal(SigningAlgorithm.ECDsaP256, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_EncryptedMLDsa65_AutoDetects()
    {
        if (!MLDsa.IsSupported) return;

        using var original = MLDsa65Signer.Generate();
        var passphrase = "test-password-mldsa";
        var encryptedPemBytes = original.ExportEncryptedPrivateKeyPemBytes(passphrase.AsSpan());
        var encryptedPem = Encoding.UTF8.GetString(encryptedPemBytes);

        using var restored = SignerFactory.CreateFromPem(encryptedPem.AsSpan(), passphrase.AsSpan());

        Assert.Equal(SigningAlgorithm.MLDsa65, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_EncryptedRsa_AutoDetects()
    {
        using var original = RsaSigner.Generate();
        var passphrase = "test-password-789";
        var encryptedPem = original.ExportEncryptedPrivateKeyPem(passphrase);

        using var restored = SignerFactory.CreateFromPem(encryptedPem.AsSpan(), passphrase.AsSpan());

        Assert.Equal(SigningAlgorithm.Rsa, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_EmptyPem_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => SignerFactory.CreateFromPem(ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void CreateFromPem_EncryptedECDsa_WrongPassphrase_ThrowsCryptographicException()
    {
        using var signer = ECDsaP256Signer.Generate();
        var encryptedPem = signer.ExportEncryptedPrivateKeyPem("correct-password");

        var ex = Assert.Throws<CryptographicException>(
            () => SignerFactory.CreateFromPem(encryptedPem.AsSpan(), "wrong-password".AsSpan()));

        Assert.Contains("passphrase", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateFromPem_EncryptedRsa_WrongPassphrase_ThrowsCryptographicException()
    {
        using var signer = RsaSigner.Generate();
        var encryptedPem = signer.ExportEncryptedPrivateKeyPem("correct-password");

        var ex = Assert.Throws<CryptographicException>(
            () => SignerFactory.CreateFromPem(encryptedPem.AsSpan(), "wrong-password".AsSpan()));

        Assert.Contains("passphrase", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateFromPem_EncryptedECDsa_WithHint_SkipsDetection()
    {
        using var original = ECDsaP256Signer.Generate();
        var passphrase = "hint-test-ec";
        var encryptedPem = original.ExportEncryptedPrivateKeyPem(passphrase);

        using var restored = SignerFactory.CreateFromPem(
            encryptedPem.AsSpan(), passphrase.AsSpan(), SigningAlgorithm.ECDsaP256);

        Assert.Equal(SigningAlgorithm.ECDsaP256, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_EncryptedRsa_WithHint_SkipsDetection()
    {
        using var original = RsaSigner.Generate();
        var passphrase = "hint-test-rsa";
        var encryptedPem = original.ExportEncryptedPrivateKeyPem(passphrase);

        using var restored = SignerFactory.CreateFromPem(
            encryptedPem.AsSpan(), passphrase.AsSpan(), SigningAlgorithm.Rsa);

        Assert.Equal(SigningAlgorithm.Rsa, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_EncryptedMLDsa65_WithHint_SkipsDetection()
    {
        if (!MLDsa.IsSupported) return;

        using var original = MLDsa65Signer.Generate();
        var passphrase = "hint-test-mldsa";
        var encryptedPemBytes = original.ExportEncryptedPrivateKeyPemBytes(passphrase.AsSpan());
        var encryptedPem = Encoding.UTF8.GetString(encryptedPemBytes);

        using var restored = SignerFactory.CreateFromPem(
            encryptedPem.AsSpan(), passphrase.AsSpan(), SigningAlgorithm.MLDsa65);

        Assert.Equal(SigningAlgorithm.MLDsa65, restored.Algorithm);
    }

    [Fact]
    public void CreateFromPem_EncryptedECDsa_WrongHint_ThrowsCryptographicException()
    {
        using var original = ECDsaP256Signer.Generate();
        var passphrase = "hint-wrong-test";
        var encryptedPem = original.ExportEncryptedPrivateKeyPem(passphrase);

        // EC key with RSA hint — should throw CryptographicException (not wrong passphrase)
        Assert.Throws<CryptographicException>(
            () => SignerFactory.CreateFromPem(
                encryptedPem.AsSpan(), passphrase.AsSpan(), SigningAlgorithm.Rsa));
    }
}
