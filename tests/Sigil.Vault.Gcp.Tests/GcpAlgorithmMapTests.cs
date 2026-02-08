using Google.Cloud.Kms.V1;
using Sigil.Crypto;
using Sigil.Vault;
using Sigil.Vault.Gcp;

namespace Sigil.Vault.Gcp.Tests;

public class GcpAlgorithmMapTests
{
    [Fact]
    public void ToGcpAlgorithm_ECDsaP256_ReturnsEcSignP256Sha256()
    {
        var result = GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.ECDsaP256);

        Assert.Equal(CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256, result);
    }

    [Fact]
    public void ToGcpAlgorithm_ECDsaP384_ReturnsEcSignP384Sha384()
    {
        var result = GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.ECDsaP384);

        Assert.Equal(CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384, result);
    }

    [Fact]
    public void ToGcpAlgorithm_Rsa_ReturnsRsaSignPss2048Sha256()
    {
        var result = GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.Rsa);

        Assert.Equal(CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss2048Sha256, result);
    }

    [Fact]
    public void ToGcpAlgorithm_Ed25519_ThrowsNotSupportedException()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.Ed25519));

        Assert.Contains("Ed25519", ex.Message);
    }

    [Fact]
    public void ToGcpAlgorithm_MLDsa65_ThrowsNotSupportedException()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.MLDsa65));

        Assert.Contains("ML-DSA-65", ex.Message);
    }

    [Fact]
    public void ToGcpAlgorithm_InvalidValue_ThrowsArgumentOutOfRangeException()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => GcpAlgorithmMap.ToGcpAlgorithm((SigningAlgorithm)999));

        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void FromGcpAlgorithm_EcSignP256Sha256_ReturnsECDsaP256()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.ECDsaP256, result.Value);
    }

    [Fact]
    public void FromGcpAlgorithm_EcSignP384Sha384_ReturnsECDsaP384()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.ECDsaP384, result.Value);
    }

    [Fact]
    public void FromGcpAlgorithm_RsaSignPss2048Sha256_ReturnsRsa()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss2048Sha256);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.Rsa, result.Value);
    }

    [Fact]
    public void FromGcpAlgorithm_RsaSignPss3072Sha256_ReturnsRsa()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss3072Sha256);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.Rsa, result.Value);
    }

    [Fact]
    public void FromGcpAlgorithm_RsaSignPss4096Sha256_ReturnsRsa()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss4096Sha256);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.Rsa, result.Value);
    }

    [Fact]
    public void FromGcpAlgorithm_RsaSignPss4096Sha512_ReturnsRsa()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss4096Sha512);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.Rsa, result.Value);
    }

    [Fact]
    public void FromGcpAlgorithm_UnsupportedAlgorithm_ReturnsFail()
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.GoogleSymmetricEncryption);

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.UnsupportedAlgorithm, result.ErrorKind);
        Assert.Contains("not supported", result.ErrorMessage);
    }

    [Theory]
    [InlineData(CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs12048Sha256)]
    [InlineData(CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaDecryptOaep2048Sha256)]
    public void FromGcpAlgorithm_NonPssRsaVariants_ReturnsFail(
        CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm gcpAlgorithm)
    {
        var result = GcpAlgorithmMap.FromGcpAlgorithm(gcpAlgorithm);

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.UnsupportedAlgorithm, result.ErrorKind);
    }

    [Fact]
    public void ToGcpAlgorithm_RoundTrip_ECDsaP256()
    {
        var gcpAlg = GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.ECDsaP256);
        var result = GcpAlgorithmMap.FromGcpAlgorithm(gcpAlg);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.ECDsaP256, result.Value);
    }

    [Fact]
    public void ToGcpAlgorithm_RoundTrip_ECDsaP384()
    {
        var gcpAlg = GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.ECDsaP384);
        var result = GcpAlgorithmMap.FromGcpAlgorithm(gcpAlg);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.ECDsaP384, result.Value);
    }

    [Fact]
    public void ToGcpAlgorithm_RoundTrip_Rsa()
    {
        var gcpAlg = GcpAlgorithmMap.ToGcpAlgorithm(SigningAlgorithm.Rsa);
        var result = GcpAlgorithmMap.FromGcpAlgorithm(gcpAlg);

        Assert.True(result.IsSuccess);
        Assert.Equal(SigningAlgorithm.Rsa, result.Value);
    }
}
