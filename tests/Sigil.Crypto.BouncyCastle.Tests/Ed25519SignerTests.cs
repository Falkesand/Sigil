using System.Text;

namespace Sigil.Crypto.BouncyCastle.Tests;

public class Ed25519SignerTests
{
    [Fact]
    public void Generate_Produces_Valid_Signer_With_Correct_Algorithm()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        Assert.Equal(SigningAlgorithm.Ed25519, signer.Algorithm);
    }

    [Fact]
    public void Sign_And_Verify_Roundtrip_Succeeds()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("hello ed25519");
        var signature = signer.Sign(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_Tampered_Data_Fails()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("original data");
        var signature = signer.Sign(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        var tampered = Encoding.UTF8.GetBytes("tampered data");
        Assert.False(verifier.Verify(tampered, signature));
    }

    [Fact]
    public void Verify_With_Wrong_Key_Fails()
    {
        using var signer1 = Ed25519BouncyCastleSigner.Generate();
        using var signer2 = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("wrong key test");
        var signature = signer1.Sign(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer2.PublicKey);
        Assert.False(verifier.Verify(data, signature));
    }

    [Fact]
    public void Export_Import_Private_Key_Pem_Roundtrip()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var pemBytes = signer.ExportPrivateKeyPemBytes();
        var pem = Encoding.UTF8.GetString(pemBytes);
        Assert.Contains("PRIVATE KEY", pem);

        using var restored = Ed25519BouncyCastleSigner.FromPem(
            new ReadOnlyMemory<char>(pem.ToCharArray()),
            ReadOnlyMemory<char>.Empty);

        Assert.Equal(SigningAlgorithm.Ed25519, restored.Algorithm);
        Assert.Equal(signer.PublicKey, restored.PublicKey);
    }

    [Fact]
    public void Export_Import_Private_Key_Pem_Sign_Verify_Roundtrip()
    {
        using var original = Ed25519BouncyCastleSigner.Generate();
        var pkcs8Pem = original.ExportPrivateKeyPemBytes();
        var data = Encoding.UTF8.GetBytes("pkcs8 roundtrip");
        var signature = original.Sign(data);

        using var restored = Ed25519BouncyCastleSigner.FromPem(
            new ReadOnlyMemory<char>(Encoding.UTF8.GetString(pkcs8Pem).ToCharArray()),
            ReadOnlyMemory<char>.Empty);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(restored.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Export_Public_Key_Pem_Contains_Header()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var publicKeyPem = signer.ExportPublicKeyPem();
        Assert.Contains("PUBLIC KEY", publicKeyPem);
    }

    [Fact]
    public void Export_Public_Key_Pem_Roundtrip_Via_Spki()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();

        // The SPKI bytes from PublicKey should roundtrip through the verifier
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        var data = Encoding.UTF8.GetBytes("public key roundtrip");
        var sig = signer.Sign(data);
        Assert.True(verifier.Verify(data, sig));
    }

    [Fact]
    public void Export_Import_Encrypted_Private_Key_Pem_Roundtrip()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var passphrase = "test-ed25519-passphrase";
        var encryptedPem = signer.ExportEncryptedPrivateKeyPemBytes(passphrase.AsSpan());
        var pem = Encoding.UTF8.GetString(encryptedPem);
        Assert.Contains("ENCRYPTED", pem);

        using var restored = Ed25519BouncyCastleSigner.FromPem(
            new ReadOnlyMemory<char>(pem.ToCharArray()),
            new ReadOnlyMemory<char>(passphrase.ToCharArray()));

        var data = Encoding.UTF8.GetBytes("encrypted roundtrip");
        var sig = restored.Sign(data);
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, sig));
    }

    [Fact]
    public void Dispose_Prevents_Sign()
    {
        var signer = Ed25519BouncyCastleSigner.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.Sign(new byte[] { 1 }));
    }

    [Fact]
    public void Dispose_Prevents_PublicKey_Access()
    {
        var signer = Ed25519BouncyCastleSigner.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = signer.PublicKey);
    }

    [Fact]
    public void Dispose_Prevents_ExportPublicKeyPem()
    {
        var signer = Ed25519BouncyCastleSigner.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.ExportPublicKeyPem());
    }

    [Fact]
    public void Dispose_Prevents_ExportPrivateKeyPemBytes()
    {
        var signer = Ed25519BouncyCastleSigner.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.ExportPrivateKeyPemBytes());
    }

    [Fact]
    public void Dispose_Prevents_ExportEncryptedPrivateKeyPemBytes()
    {
        var signer = Ed25519BouncyCastleSigner.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.ExportEncryptedPrivateKeyPemBytes("pass".AsSpan()));
    }

    [Fact]
    public void Sign_Null_Data_Throws_ArgumentNullException()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        Assert.Throws<ArgumentNullException>(() => signer.Sign(null!));
    }

    [Fact]
    public void ExportEncryptedPrivateKeyPemBytes_Empty_Password_Throws()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        Assert.Throws<ArgumentException>(() => signer.ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void PublicKey_Returns_44_Byte_Spki()
    {
        // Ed25519 SPKI: 12-byte header + 32-byte key = 44 bytes
        using var signer = Ed25519BouncyCastleSigner.Generate();
        Assert.Equal(44, signer.PublicKey.Length);
    }

    [Fact]
    public void Signature_Is_64_Bytes()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("signature length test");
        var signature = signer.Sign(data);
        Assert.Equal(64, signature.Length);
    }

    [Fact]
    public void Sign_Empty_Data_Succeeds()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Array.Empty<byte>();
        var signature = signer.Sign(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void CanExportPrivateKey_Returns_True()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        Assert.True(signer.CanExportPrivateKey);
    }

    [Fact]
    public async Task SignAsync_Delegates_To_Sign()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("async sign test");
        var signature = await signer.SignAsync(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void FromPkcs8_Null_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Ed25519BouncyCastleSigner.FromPkcs8(null!));
    }

    [Fact]
    public void FromPem_Invalid_Pem_Throws_FormatException()
    {
        var invalidPem = "not a valid pem".ToCharArray();
        Assert.Throws<FormatException>(() => Ed25519BouncyCastleSigner.FromPem(
            new ReadOnlyMemory<char>(invalidPem),
            ReadOnlyMemory<char>.Empty));
    }

    [Fact]
    public void Generate_Produces_Unique_Keys()
    {
        using var signer1 = Ed25519BouncyCastleSigner.Generate();
        using var signer2 = Ed25519BouncyCastleSigner.Generate();
        Assert.NotEqual(signer1.PublicKey, signer2.PublicKey);
    }

    [Fact]
    public void Sign_Produces_Deterministic_Signatures()
    {
        // Ed25519 signatures are deterministic (no random nonce)
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("deterministic test");
        var sig1 = signer.Sign(data);
        var sig2 = signer.Sign(data);
        Assert.Equal(sig1, sig2);
    }
}
