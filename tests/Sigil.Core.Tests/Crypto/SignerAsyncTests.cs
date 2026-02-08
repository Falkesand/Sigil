using System.Text;
using Sigil.Crypto;

namespace Sigil.Core.Tests.Crypto;

public class SignerAsyncTests
{
    [Fact]
    public async Task ECDsaP256_SignAsync_ReturnsSameAsSign()
    {
        using var signer = ECDsaP256Signer.Generate();
        var data = Encoding.UTF8.GetBytes("test data");

        var syncSig = signer.Sign(data);
        var asyncSig = await signer.SignAsync(data);

        // Both should produce valid signatures (non-deterministic, so verify instead of equality)
        var verifier = ECDsaP256Verifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, syncSig));
        Assert.True(verifier.Verify(data, asyncSig));
    }

    [Fact]
    public void ECDsaP256_CanExportPrivateKey_ReturnsTrue()
    {
        using var signer = ECDsaP256Signer.Generate();
        Assert.True(signer.CanExportPrivateKey);
    }

    [Fact]
    public async Task ECDsaP384_SignAsync_ProducesValidSignature()
    {
        using var signer = ECDsaP384Signer.Generate();
        var data = Encoding.UTF8.GetBytes("test data");

        var signature = await signer.SignAsync(data);

        var verifier = ECDsaP384Verifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ECDsaP384_CanExportPrivateKey_ReturnsTrue()
    {
        using var signer = ECDsaP384Signer.Generate();
        Assert.True(signer.CanExportPrivateKey);
    }

    [Fact]
    public async Task Rsa_SignAsync_ProducesValidSignature()
    {
        using var signer = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("test data");

        var signature = await signer.SignAsync(data);

        var verifier = RsaVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Rsa_CanExportPrivateKey_ReturnsTrue()
    {
        using var signer = RsaSigner.Generate();
        Assert.True(signer.CanExportPrivateKey);
    }
}
