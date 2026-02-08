using Sigil.Crypto;
using Sigil.Vault.HashiCorp;
using VaultSharp.V1.SecretsEngines.Transit;

namespace Sigil.Vault.HashiCorp.Tests;

public class HashiCorpAlgorithmMapTests
{
    [Fact]
    public void FromTransitKeyType_EcdsaP256_ReturnsECDsaP256()
    {
        var result = HashiCorpAlgorithmMap.FromTransitKeyType(TransitKeyType.ecdsa_p256);

        Assert.Equal(SigningAlgorithm.ECDsaP256, result);
    }

    [Fact]
    public void FromTransitKeyType_EcdsaP384_ReturnsECDsaP384()
    {
        var result = HashiCorpAlgorithmMap.FromTransitKeyType(TransitKeyType.ecdsa_p384);

        Assert.Equal(SigningAlgorithm.ECDsaP384, result);
    }

    [Theory]
    [InlineData(TransitKeyType.rsa_2048)]
    [InlineData(TransitKeyType.rsa_3072)]
    [InlineData(TransitKeyType.rsa_4096)]
    public void FromTransitKeyType_RsaVariants_ReturnsRsa(TransitKeyType keyType)
    {
        var result = HashiCorpAlgorithmMap.FromTransitKeyType(keyType);

        Assert.Equal(SigningAlgorithm.Rsa, result);
    }

    [Fact]
    public void FromTransitKeyType_UnsupportedType_ReturnsNull()
    {
        var result = HashiCorpAlgorithmMap.FromTransitKeyType(TransitKeyType.aes256_gcm96);

        Assert.Null(result);
    }

    [Theory]
    [InlineData(TransitKeyType.aes128_gcm96)]
    [InlineData(TransitKeyType.chacha20_poly1305)]
    public void FromTransitKeyType_SymmetricTypes_ReturnsNull(TransitKeyType keyType)
    {
        var result = HashiCorpAlgorithmMap.FromTransitKeyType(keyType);

        Assert.Null(result);
    }

    [Fact]
    public void ToTransitHashAlgorithm_ECDsaP256_ReturnsSha256()
    {
        var result = HashiCorpAlgorithmMap.ToTransitHashAlgorithm(SigningAlgorithm.ECDsaP256);

        Assert.Equal(TransitHashAlgorithm.SHA2_256, result);
    }

    [Fact]
    public void ToTransitHashAlgorithm_ECDsaP384_ReturnsSha384()
    {
        var result = HashiCorpAlgorithmMap.ToTransitHashAlgorithm(SigningAlgorithm.ECDsaP384);

        Assert.Equal(TransitHashAlgorithm.SHA2_384, result);
    }

    [Fact]
    public void ToTransitHashAlgorithm_Rsa_ReturnsSha256()
    {
        var result = HashiCorpAlgorithmMap.ToTransitHashAlgorithm(SigningAlgorithm.Rsa);

        Assert.Equal(TransitHashAlgorithm.SHA2_256, result);
    }

    [Fact]
    public void ToTransitHashAlgorithm_Ed25519_ThrowsArgumentOutOfRange()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => HashiCorpAlgorithmMap.ToTransitHashAlgorithm(SigningAlgorithm.Ed25519));

        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void ToTransitHashAlgorithm_MLDsa65_ThrowsArgumentOutOfRange()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => HashiCorpAlgorithmMap.ToTransitHashAlgorithm(SigningAlgorithm.MLDsa65));

        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void ToTransitSignatureAlgorithm_Rsa_ReturnsPss()
    {
        var result = HashiCorpAlgorithmMap.ToTransitSignatureAlgorithm(SigningAlgorithm.Rsa);

        Assert.Equal(SignatureAlgorithm.pss, result);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    public void ToTransitSignatureAlgorithm_EcTypes_ReturnsNull(SigningAlgorithm algorithm)
    {
        var result = HashiCorpAlgorithmMap.ToTransitSignatureAlgorithm(algorithm);

        Assert.Null(result);
    }

    [Fact]
    public void ToTransitSignatureAlgorithm_Ed25519_ReturnsNull()
    {
        var result = HashiCorpAlgorithmMap.ToTransitSignatureAlgorithm(SigningAlgorithm.Ed25519);

        Assert.Null(result);
    }

    [Fact]
    public void ToTransitSignatureAlgorithm_MLDsa65_ReturnsNull()
    {
        var result = HashiCorpAlgorithmMap.ToTransitSignatureAlgorithm(SigningAlgorithm.MLDsa65);

        Assert.Null(result);
    }
}
