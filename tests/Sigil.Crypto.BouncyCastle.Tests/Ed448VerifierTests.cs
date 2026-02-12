using System.Text;

namespace Sigil.Crypto.BouncyCastle.Tests;

public class Ed448VerifierTests
{
    [Fact]
    public void FromPublicKey_With_Valid_Spki_Creates_Verifier()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.NotNull(verifier);
    }

    [Fact]
    public void Verify_Valid_Signature_Returns_True()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("valid signature test");
        var signature = signer.Sign(data);

        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_Invalid_Signature_Returns_False()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("valid data");
        var badSignature = new byte[114]; // all zeros

        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(data, badSignature));
    }

    [Fact]
    public void Verify_Null_Data_Throws_ArgumentNullException()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Throws<ArgumentNullException>(() => verifier.Verify(null!, new byte[114]));
    }

    [Fact]
    public void Verify_Null_Signature_Throws_ArgumentNullException()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Throws<ArgumentNullException>(() => verifier.Verify(new byte[] { 1 }, null!));
    }

    [Fact]
    public void Dispose_Prevents_Verify()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        verifier.Dispose();

        Assert.Throws<ObjectDisposedException>(() => verifier.Verify(new byte[] { 1 }, new byte[114]));
    }

    [Fact]
    public void Dispose_Prevents_PublicKey_Access()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        verifier.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = verifier.PublicKey);
    }

    [Fact]
    public void Algorithm_Returns_Ed448()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Equal(SigningAlgorithm.Ed448, verifier.Algorithm);
    }

    [Fact]
    public void FromPublicKey_Null_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Ed448BouncyCastleVerifier.FromPublicKey(null!));
    }

    [Fact]
    public void PublicKey_Roundtrips_Through_Spki()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var originalSpki = signer.PublicKey;

        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(originalSpki);
        var roundtrippedSpki = verifier.PublicKey;

        Assert.Equal(originalSpki, roundtrippedSpki);
    }

    [Fact]
    public void PublicKey_Returns_Expected_Spki_Size()
    {
        // Ed448 SPKI: 12-byte header + 57-byte key = 69 bytes
        using var signer = Ed448BouncyCastleSigner.Generate();
        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.Equal(69, verifier.PublicKey.Length);
    }

    [Fact]
    public void Verify_Truncated_Signature_Returns_False()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("truncation test");
        var signature = signer.Sign(data);

        // Truncate to 57 bytes
        var truncated = new byte[57];
        Array.Copy(signature, truncated, 57);

        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(data, truncated));
    }

    [Fact]
    public void Verify_Empty_Data_With_Valid_Signature_Succeeds()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var data = Array.Empty<byte>();
        var signature = signer.Sign(data);

        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_With_Flipped_Signature_Bit_Returns_False()
    {
        using var signer = Ed448BouncyCastleSigner.Generate();
        var data = Encoding.UTF8.GetBytes("bit flip test");
        var signature = signer.Sign(data);

        // Flip one bit in the signature
        var corrupted = (byte[])signature.Clone();
        corrupted[0] ^= 0x01;

        using var verifier = Ed448BouncyCastleVerifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(data, corrupted));
    }
}
