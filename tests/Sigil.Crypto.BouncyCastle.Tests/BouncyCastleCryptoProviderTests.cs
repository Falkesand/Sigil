using System.Text;
using Sigil.Crypto;
using Sigil.Crypto.BouncyCastle;

namespace Sigil.Crypto.BouncyCastle.Tests;

[Collection("CryptoProviderRegistry")]
public class BouncyCastleCryptoProviderTests : IDisposable
{
    public BouncyCastleCryptoProviderTests()
    {
        CryptoProviderRegistry.Reset();
    }

    public void Dispose()
    {
        CryptoProviderRegistry.Reset();
    }

    [Fact]
    public void Register_Makes_Ed25519_Available_Via_SignerFactory_Generate()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed25519);
        Assert.Equal(SigningAlgorithm.Ed25519, signer.Algorithm);
    }

    [Fact]
    public void Register_Makes_Ed448_Available_Via_SignerFactory_Generate()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed448);
        Assert.Equal(SigningAlgorithm.Ed448, signer.Algorithm);
    }

    [Fact]
    public void Ed25519_Full_Sign_Verify_Roundtrip_Via_Factories()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed25519);
        var data = Encoding.UTF8.GetBytes("factory ed25519 roundtrip");
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(signer.PublicKey, "ed25519");
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Ed448_Full_Sign_Verify_Roundtrip_Via_Factories()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed448);
        var data = Encoding.UTF8.GetBytes("factory ed448 roundtrip");
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(signer.PublicKey, "ed448");
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Ed25519_VerifierFactory_CreateFromPublicKey_Works()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed25519);
        using var verifier = VerifierFactory.CreateFromPublicKey(signer.PublicKey, "ed25519");
        Assert.Equal(SigningAlgorithm.Ed25519, verifier.Algorithm);
    }

    [Fact]
    public void Ed448_VerifierFactory_CreateFromPublicKey_Works()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed448);
        using var verifier = VerifierFactory.CreateFromPublicKey(signer.PublicKey, "ed448");
        Assert.Equal(SigningAlgorithm.Ed448, verifier.Algorithm);
    }

    [Fact]
    public void Ed25519_SignerFactory_CreateFromPem_Works()
    {
        BouncyCastleCryptoProvider.Register();
        using var original = SignerFactory.Generate(SigningAlgorithm.Ed25519);
        var pemBytes = original.ExportPrivateKeyPemBytes();
        var pem = Encoding.UTF8.GetString(pemBytes);

        using var restored = SignerFactory.CreateFromPem(pem.AsSpan());
        Assert.Equal(SigningAlgorithm.Ed25519, restored.Algorithm);
    }

    [Fact]
    public void Ed448_SignerFactory_CreateFromPem_Works()
    {
        BouncyCastleCryptoProvider.Register();
        using var original = SignerFactory.Generate(SigningAlgorithm.Ed448);
        var pemBytes = original.ExportPrivateKeyPemBytes();
        var pem = Encoding.UTF8.GetString(pemBytes);

        using var restored = SignerFactory.CreateFromPem(pem.AsSpan());
        Assert.Equal(SigningAlgorithm.Ed448, restored.Algorithm);
    }

    [Fact]
    public void Register_Is_Idempotent()
    {
        BouncyCastleCryptoProvider.Register();
        // Second call should not throw
        BouncyCastleCryptoProvider.Register();

        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed25519);
        Assert.Equal(SigningAlgorithm.Ed25519, signer.Algorithm);
    }

    [Fact]
    public void Existing_Algorithms_Still_Work_After_Registration()
    {
        BouncyCastleCryptoProvider.Register();
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }
}
