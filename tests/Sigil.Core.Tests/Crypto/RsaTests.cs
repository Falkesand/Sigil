using Sigil.Crypto;
using System.Text;

namespace Sigil.Core.Tests.Crypto;

public class RsaTests
{
    [Fact]
    public void Generate_ProducesValidSigner()
    {
        using var signer = RsaSigner.Generate();
        Assert.Equal(SigningAlgorithm.Rsa, signer.Algorithm);
        Assert.NotNull(signer.PublicKey);
        Assert.True(signer.PublicKey.Length > 0);
    }

    [Fact]
    public void Generate_CustomKeySize_Succeeds()
    {
        using var signer = RsaSigner.Generate(4096);
        Assert.Equal(SigningAlgorithm.Rsa, signer.Algorithm);
        Assert.NotNull(signer.PublicKey);
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        using var signer = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("test message for RSA signing");

        var signature = signer.Sign(data);
        Assert.NotNull(signature);

        using var verifier = RsaVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_TamperedData_Fails()
    {
        using var signer = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("original message");
        var signature = signer.Sign(data);

        var tampered = Encoding.UTF8.GetBytes("tampered message");
        using var verifier = RsaVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(tampered, signature));
    }

    [Fact]
    public void Verify_WrongKey_Fails()
    {
        using var signer1 = RsaSigner.Generate();
        using var signer2 = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("message signed by key 1");
        var signature = signer1.Sign(data);

        using var verifierWithKey2 = RsaVerifier.FromPublicKey(signer2.PublicKey);
        Assert.False(verifierWithKey2.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_Pkcs8_RoundTrip()
    {
        using var original = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("round trip test");

        var pkcs8 = original.ExportPkcs8();
        using var restored = RsaSigner.FromPkcs8(pkcs8);

        using var verifier = RsaVerifier.FromPublicKey(original.PublicKey);
        var newSig = restored.Sign(data);
        Assert.True(verifier.Verify(data, newSig));
    }

    [Fact]
    public void ExportImport_EncryptedPkcs8_RoundTrip()
    {
        using var original = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("encrypted key test");
        var password = "test-passphrase-123";

        var encrypted = original.ExportEncryptedPkcs8(password);
        using var restored = RsaSigner.FromEncryptedPkcs8(encrypted, password);

        using var verifier = RsaVerifier.FromPublicKey(original.PublicKey);
        var signature = restored.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_Pem_RoundTrip()
    {
        using var signer = RsaSigner.Generate();
        var pem = signer.ExportPublicKeyPem();

        Assert.Contains("BEGIN PUBLIC KEY", pem);
        Assert.Contains("END PUBLIC KEY", pem);

        using var verifier = RsaVerifier.FromPublicKeyPem(pem);
        var data = Encoding.UTF8.GetBytes("PEM round trip");
        var signature = signer.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_PrivateKeyPem_RoundTrip()
    {
        using var original = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("private pem round trip");
        var pem = original.ExportPrivateKeyPem();

        using var restored = RsaSigner.FromPem(pem.AsSpan());

        using var verifier = RsaVerifier.FromPublicKey(original.PublicKey);
        var signature = restored.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Dispose_PreventsFurtherUse()
    {
        var signer = RsaSigner.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.Sign([]));
    }

    [Fact]
    public void Verifier_Dispose_DoesNotThrow()
    {
        using var signer = RsaSigner.Generate();
        using var verifier = RsaVerifier.FromPublicKey(signer.PublicKey);

        var ex = Record.Exception(() => verifier.Dispose());
        Assert.Null(ex);
    }

    [Fact]
    public void Verifier_Disposed_Verify_Throws()
    {
        using var signer = RsaSigner.Generate();
        var data = Encoding.UTF8.GetBytes("test");
        var signature = signer.Sign(data);

        var verifier = RsaVerifier.FromPublicKey(signer.PublicKey);
        verifier.Dispose();

        Assert.Throws<ObjectDisposedException>(() => verifier.Verify(data, signature));
    }

    [Fact]
    public void Verifier_Disposed_PublicKey_Throws()
    {
        using var signer = RsaSigner.Generate();
        var verifier = RsaVerifier.FromPublicKey(signer.PublicKey);
        verifier.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = verifier.PublicKey);
    }
}
