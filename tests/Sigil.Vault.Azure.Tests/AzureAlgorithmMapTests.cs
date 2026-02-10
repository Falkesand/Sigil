using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Sigil.Crypto;
using Sigil.Vault.Azure;

namespace Sigil.Vault.Azure.Tests;

public class AzureAlgorithmMapTests
{
    [Fact]
    public void TryGetAzureAlgorithm_ECDsaP256_ReturnsES256()
    {
        var result = AzureAlgorithmMap.TryGetAzureAlgorithm(SigningAlgorithm.ECDsaP256, out var azureAlgorithm);

        Assert.True(result);
        Assert.Equal(SignatureAlgorithm.ES256, azureAlgorithm);
    }

    [Fact]
    public void TryGetAzureAlgorithm_ECDsaP384_ReturnsES384()
    {
        var result = AzureAlgorithmMap.TryGetAzureAlgorithm(SigningAlgorithm.ECDsaP384, out var azureAlgorithm);

        Assert.True(result);
        Assert.Equal(SignatureAlgorithm.ES384, azureAlgorithm);
    }

    [Fact]
    public void TryGetAzureAlgorithm_ECDsaP521_ReturnsES512()
    {
        var result = AzureAlgorithmMap.TryGetAzureAlgorithm(SigningAlgorithm.ECDsaP521, out var azureAlgorithm);

        Assert.True(result);
        Assert.Equal(SignatureAlgorithm.ES512, azureAlgorithm);
    }

    [Fact]
    public void TryGetAzureAlgorithm_Rsa_ReturnsPS256()
    {
        var result = AzureAlgorithmMap.TryGetAzureAlgorithm(SigningAlgorithm.Rsa, out var azureAlgorithm);

        Assert.True(result);
        Assert.Equal(SignatureAlgorithm.PS256, azureAlgorithm);
    }

    [Theory]
    [InlineData(SigningAlgorithm.Ed25519)]
    [InlineData(SigningAlgorithm.MLDsa65)]
    public void TryGetAzureAlgorithm_UnsupportedAlgorithm_ReturnsFalse(SigningAlgorithm algorithm)
    {
        var result = AzureAlgorithmMap.TryGetAzureAlgorithm(algorithm, out var azureAlgorithm);

        Assert.False(result);
        Assert.Null(azureAlgorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcP256_ReturnsECDsaP256()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Ec, KeyCurveName.P256, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.ECDsaP256, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcP384_ReturnsECDsaP384()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Ec, KeyCurveName.P384, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.ECDsaP384, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcP521_ReturnsECDsaP521()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Ec, KeyCurveName.P521, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.ECDsaP521, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcHsmP521_ReturnsECDsaP521()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.EcHsm, KeyCurveName.P521, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.ECDsaP521, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_Rsa_ReturnsRsa()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Rsa, null, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.Rsa, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcHsm_Supported()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.EcHsm, KeyCurveName.P256, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.ECDsaP256, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_RsaHsm_Supported()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.RsaHsm, null, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.Rsa, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_UnsupportedKeyType_ReturnsFalse()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Oct, null, out var algorithm);

        Assert.False(result);
        Assert.Equal(default, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcWithUnsupportedCurve_ReturnsFalse()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Ec, KeyCurveName.P256K, out var algorithm);

        Assert.False(result);
        Assert.Equal(default, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcWithNullCurve_ReturnsFalse()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.Ec, null, out var algorithm);

        Assert.False(result);
        Assert.Equal(default, algorithm);
    }

    [Fact]
    public void TryGetSigningAlgorithm_EcHsmP384_ReturnsECDsaP384()
    {
        var result = AzureAlgorithmMap.TryGetSigningAlgorithm(KeyType.EcHsm, KeyCurveName.P384, out var algorithm);

        Assert.True(result);
        Assert.Equal(SigningAlgorithm.ECDsaP384, algorithm);
    }
}
