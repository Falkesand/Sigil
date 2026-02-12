using System.Text;

namespace Sigil.Crypto.BouncyCastle.Tests;

public class Ed25519VerifierTests
{
    [Fact]
    public void FromPublicKey_With_Valid_Spki_Creates_Verifier()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.NotNull(verifier);
    }

    [Fact]
    public void Verify_Valid_Signature_Returns_True()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("valid signature test");
        var signature = signer.Sign(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_Invalid_Signature_Returns_False()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("valid data");
        var badSignature = new byte[64]; // all zeros

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(data, badSignature));
    }

    [Fact]
    public void Verify_Null_Data_Throws_ArgumentNullException()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Throws<ArgumentNullException>(() => verifier.Verify(null!, new byte[64]));
    }

    [Fact]
    public void Verify_Null_Signature_Throws_ArgumentNullException()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Throws<ArgumentNullException>(() => verifier.Verify(new byte[] { 1 }, null!));
    }

    [Fact]
    public void Dispose_Prevents_Verify()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        verifier.Dispose();

        Assert.Throws<ObjectDisposedException>(() => verifier.Verify(new byte[] { 1 }, new byte[64]));
    }

    [Fact]
    public void Dispose_Prevents_PublicKey_Access()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        verifier.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = verifier.PublicKey);
    }

    [Fact]
    public void Algorithm_Returns_Ed25519()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Equal(SigningAlgorithm.Ed25519, verifier.Algorithm);
    }

    [Fact]
    public void FromPublicKey_Null_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Ed25519BouncyCastleVerifier.FromPublicKey(null!));
    }

    [Fact]
    public void PublicKey_Roundtrips_Through_Spki()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var originalSpki = signer.PublicKey;

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(originalSpki);
        var roundtrippedSpki = verifier.PublicKey;

        Assert.Equal(originalSpki, roundtrippedSpki);
    }

    [Fact]
    public void PublicKey_Returns_44_Byte_Spki()
    {
        // Ed25519 SPKI: 12-byte header + 32-byte key = 44 bytes
        using var signer = Ed25519BouncyCastleSigner.Generate();
        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Equal(44, verifier.PublicKey.Length);
    }

    [Fact]
    public void Verify_Truncated_Signature_Returns_False()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("truncation test");
        var signature = signer.Sign(data);

        // Truncate to 32 bytes
        var truncated = new byte[32];
        Array.Copy(signature, truncated, 32);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(data, truncated));
    }

    [Fact]
    public void Verify_Empty_Data_With_Valid_Signature_Succeeds()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Array.Empty<byte>();
        var signature = signer.Sign(data);

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_With_Flipped_Signature_Bit_Returns_False()
    {
        using var signer = Ed25519BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("bit flip test");
        var signature = signer.Sign(data);

        // Flip one bit in the signature
        var corrupted = (byte[])signature.Clone();
        corrupted[0] ^= 0x01;

        using var verifier = Ed25519BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(data, corrupted));
    }
}
