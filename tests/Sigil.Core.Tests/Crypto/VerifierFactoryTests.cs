using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;

namespace Sigil.Core.Tests.Crypto;

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
