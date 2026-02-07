using Sigil.Crypto;
using System.Text;

namespace Sigil.Core.Tests.Crypto;

public class ECDsaP256Tests
{
    [Fact]
    public void Generate_ProducesValidSigner()
    {
        using var signer = ECDsaP256Signer.Generate();
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
        Assert.NotNull(signer.PublicKey);
        Assert.True(signer.PublicKey.Length > 0);
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        using var signer = ECDsaP256Signer.Generate();
        var data = Encoding.UTF8.GetBytes("test message for signing");

        var signature = signer.Sign(data);
        Assert.NotNull(signature);

        var verifier = ECDsaP256Verifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_TamperedData_Fails()
    {
        using var signer = ECDsaP256Signer.Generate();
        var data = Encoding.UTF8.GetBytes("original message");
        var signature = signer.Sign(data);

        var tampered = Encoding.UTF8.GetBytes("tampered message");
        var verifier = ECDsaP256Verifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(tampered, signature));
    }

    [Fact]
    public void Verify_WrongKey_Fails()
    {
        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var data = Encoding.UTF8.GetBytes("message signed by key 1");
        var signature = signer1.Sign(data);

        var verifierWithKey2 = ECDsaP256Verifier.FromPublicKey(signer2.PublicKey);
        Assert.False(verifierWithKey2.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_Pkcs8_RoundTrip()
    {
        using var original = ECDsaP256Signer.Generate();
        var data = Encoding.UTF8.GetBytes("round trip test");
        var signature = original.Sign(data);

        var pkcs8 = original.ExportPkcs8();
        using var restored = ECDsaP256Signer.FromPkcs8(pkcs8);

        // Restored signer should produce verifiable signatures with same public key
        var verifier = ECDsaP256Verifier.FromPublicKey(original.PublicKey);
        var newSig = restored.Sign(data);
        Assert.True(verifier.Verify(data, newSig));
    }

    [Fact]
    public void ExportImport_EncryptedPkcs8_RoundTrip()
    {
        using var original = ECDsaP256Signer.Generate();
        var data = Encoding.UTF8.GetBytes("encrypted key test");
        var password = "test-passphrase-123";

        var encrypted = original.ExportEncryptedPkcs8(password);
        using var restored = ECDsaP256Signer.FromEncryptedPkcs8(encrypted, password);

        var verifier = ECDsaP256Verifier.FromPublicKey(original.PublicKey);
        var signature = restored.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_Pem_RoundTrip()
    {
        using var signer = ECDsaP256Signer.Generate();
        var pem = signer.ExportPublicKeyPem();

        Assert.Contains("BEGIN PUBLIC KEY", pem);
        Assert.Contains("END PUBLIC KEY", pem);

        var verifier = ECDsaP256Verifier.FromPublicKeyPem(pem);
        var data = Encoding.UTF8.GetBytes("PEM round trip");
        var signature = signer.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Dispose_PreventsFurtherUse()
    {
        var signer = ECDsaP256Signer.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.Sign([]));
    }
}
