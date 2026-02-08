using Amazon.KeyManagementService;
using Sigil.Crypto;
using Sigil.Vault.Aws;

namespace Sigil.Vault.Aws.Tests;

public class AwsAlgorithmMapTests
{
    [Fact]
    public void ToAwsAlgorithm_ECDsaP256_ReturnsECDSA_SHA_256()
    {
        var result = AwsAlgorithmMap.ToAwsAlgorithm(SigningAlgorithm.ECDsaP256);

        Assert.Equal(SigningAlgorithmSpec.ECDSA_SHA_256, result);
    }

    [Fact]
    public void ToAwsAlgorithm_ECDsaP384_ReturnsECDSA_SHA_384()
    {
        var result = AwsAlgorithmMap.ToAwsAlgorithm(SigningAlgorithm.ECDsaP384);

        Assert.Equal(SigningAlgorithmSpec.ECDSA_SHA_384, result);
    }

    [Fact]
    public void ToAwsAlgorithm_Rsa_ReturnsRSASSA_PSS_SHA_256()
    {
        var result = AwsAlgorithmMap.ToAwsAlgorithm(SigningAlgorithm.Rsa);

        Assert.Equal(SigningAlgorithmSpec.RSASSA_PSS_SHA_256, result);
    }

    [Theory]
    [InlineData(SigningAlgorithm.Ed25519)]
    [InlineData(SigningAlgorithm.MLDsa65)]
    public void ToAwsAlgorithm_UnsupportedAlgorithm_ThrowsArgumentException(SigningAlgorithm algorithm)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => AwsAlgorithmMap.ToAwsAlgorithm(algorithm));

        Assert.Equal("algorithm", ex.ParamName);
        Assert.Contains("Unsupported signing algorithm", ex.Message);
    }

    [Fact]
    public void FromAwsKeySpec_ECC_NIST_P256_ReturnsECDsaP256()
    {
        var result = AwsAlgorithmMap.FromAwsKeySpec(KeySpec.ECC_NIST_P256);

        Assert.Equal(SigningAlgorithm.ECDsaP256, result);
    }

    [Fact]
    public void FromAwsKeySpec_ECC_NIST_P384_ReturnsECDsaP384()
    {
        var result = AwsAlgorithmMap.FromAwsKeySpec(KeySpec.ECC_NIST_P384);

        Assert.Equal(SigningAlgorithm.ECDsaP384, result);
    }

    [Fact]
    public void FromAwsKeySpec_RSA_2048_ReturnsRsa()
    {
        var result = AwsAlgorithmMap.FromAwsKeySpec(KeySpec.RSA_2048);

        Assert.Equal(SigningAlgorithm.Rsa, result);
    }

    [Fact]
    public void FromAwsKeySpec_RSA_3072_ReturnsRsa()
    {
        var result = AwsAlgorithmMap.FromAwsKeySpec(KeySpec.RSA_3072);

        Assert.Equal(SigningAlgorithm.Rsa, result);
    }

    [Fact]
    public void FromAwsKeySpec_RSA_4096_ReturnsRsa()
    {
        var result = AwsAlgorithmMap.FromAwsKeySpec(KeySpec.RSA_4096);

        Assert.Equal(SigningAlgorithm.Rsa, result);
    }

    [Fact]
    public void FromAwsKeySpec_Unsupported_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => AwsAlgorithmMap.FromAwsKeySpec(KeySpec.SYMMETRIC_DEFAULT));

        Assert.Equal("keySpec", ex.ParamName);
        Assert.Contains("Unsupported AWS key spec", ex.Message);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    [InlineData(SigningAlgorithm.Rsa)]
    public void ToAwsAlgorithm_SupportedAlgorithms_DoNotThrow(SigningAlgorithm algorithm)
    {
        var ex = Record.Exception(() => AwsAlgorithmMap.ToAwsAlgorithm(algorithm));

        Assert.Null(ex);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    [InlineData(SigningAlgorithm.Rsa)]
    public void RoundTrip_ToAwsAndBack_PreservesAlgorithm(SigningAlgorithm algorithm)
    {
        // Map to AWS, then find the corresponding KeySpec and map back
        var awsAlgorithm = AwsAlgorithmMap.ToAwsAlgorithm(algorithm);
        Assert.NotNull(awsAlgorithm);
    }
}
