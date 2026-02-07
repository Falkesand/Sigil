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
}

public class VerifierFactoryTests
{
    [Fact]
    public void CreateFromPublicKey_ECDsaP256_ReturnsCorrectVerifier()
    {
        using var signer = ECDsaP256Signer.Generate();
        var spki = signer.PublicKey;
        var algorithmName = SigningAlgorithm.ECDsaP256.ToCanonicalName();

        using var verifier = VerifierFactory.CreateFromPublicKey(spki, algorithmName);

        Assert.Equal(SigningAlgorithm.ECDsaP256, verifier.Algorithm);
    }

    [Fact]
    public void CreateFromPublicKey_ECDsaP384_ReturnsCorrectVerifier()
    {
        using var signer = ECDsaP384Signer.Generate();
        var spki = signer.PublicKey;
        var algorithmName = SigningAlgorithm.ECDsaP384.ToCanonicalName();

        using var verifier = VerifierFactory.CreateFromPublicKey(spki, algorithmName);

        Assert.Equal(SigningAlgorithm.ECDsaP384, verifier.Algorithm);
    }

    [Fact]
    public void CreateFromPublicKey_Rsa_ReturnsCorrectVerifier()
    {
        using var signer = RsaSigner.Generate();
        var spki = signer.PublicKey;
        var algorithmName = SigningAlgorithm.Rsa.ToCanonicalName();

        using var verifier = VerifierFactory.CreateFromPublicKey(spki, algorithmName);

        Assert.Equal(SigningAlgorithm.Rsa, verifier.Algorithm);
    }

    [Fact]
    public void CreateFromPublicKey_SignAndVerify_RoundTrip()
    {
        using var signer = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("verifier factory round trip");
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            signer.PublicKey, SigningAlgorithm.Rsa.ToCanonicalName());

        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void CreateFromPublicKey_Ed25519_ThrowsNotSupportedException()
    {
        Assert.Throws<NotSupportedException>(() =>
            VerifierFactory.CreateFromPublicKey(new byte[] { 0 }, "ed25519"));
    }
}
