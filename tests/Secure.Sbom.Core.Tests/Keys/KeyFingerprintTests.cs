using Secure.Sbom.Crypto;
using Secure.Sbom.Keys;

namespace Secure.Sbom.Core.Tests.Keys;

public class KeyFingerprintTests
{
    [Fact]
    public void Compute_FromSPKI_ProducesValidFingerprint()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        Assert.StartsWith("sha256:", fp.Value);
        Assert.Equal(71, fp.Value.Length); // "sha256:" (7) + 64 hex chars
    }

    [Fact]
    public void Compute_DifferentKeys_DifferentFingerprints()
    {
        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();

        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        Assert.NotEqual(fp1, fp2);
    }

    [Fact]
    public void Compute_SameKey_SameFingerprint()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer.PublicKey);

        Assert.Equal(fp1, fp2);
    }

    [Fact]
    public void Parse_ValidFingerprint_Succeeds()
    {
        var fp = KeyFingerprint.Parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        Assert.Equal("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", fp.Value);
    }

    [Fact]
    public void Parse_InvalidPrefix_Throws()
    {
        Assert.Throws<FormatException>(() => KeyFingerprint.Parse("md5:0123456789abcdef"));
    }

    [Fact]
    public void Parse_InvalidLength_Throws()
    {
        Assert.Throws<FormatException>(() => KeyFingerprint.Parse("sha256:0123"));
    }

    [Fact]
    public void ShortId_TruncatesCorrectly()
    {
        var fp = KeyFingerprint.Parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        Assert.Equal("sha256:0123456789abc", fp.ShortId);
    }

    [Fact]
    public void Equality_Works()
    {
        var fp1 = KeyFingerprint.Parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        var fp2 = KeyFingerprint.Parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        Assert.Equal(fp1, fp2);
        Assert.True(fp1 == fp2);
        Assert.False(fp1 != fp2);
    }
}
