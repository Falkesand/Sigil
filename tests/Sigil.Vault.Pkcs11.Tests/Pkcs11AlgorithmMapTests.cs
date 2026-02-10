using Net.Pkcs11Interop.Common;
using Sigil.Crypto;
using Sigil.Vault.Pkcs11;

namespace Sigil.Vault.Pkcs11.Tests;

public class Pkcs11AlgorithmMapTests
{
    // DER-encoded OID for P-256: 06 08 2A 86 48 CE 3D 03 01 07
    private static readonly byte[] EcParamsP256 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // DER-encoded OID for P-384: 06 05 2B 81 04 00 22
    private static readonly byte[] EcParamsP384 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

    // DER-encoded OID for P-521: 06 05 2B 81 04 00 23
    private static readonly byte[] EcParamsP521 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

    [Fact]
    public void FromPkcs11KeyType_EcWithP256Params_ReturnsECDsaP256()
    {
        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_EC, EcParamsP256);

        Assert.Equal(SigningAlgorithm.ECDsaP256, result);
    }

    [Fact]
    public void FromPkcs11KeyType_EcWithP384Params_ReturnsECDsaP384()
    {
        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_EC, EcParamsP384);

        Assert.Equal(SigningAlgorithm.ECDsaP384, result);
    }

    [Fact]
    public void FromPkcs11KeyType_EcWithP521Params_ReturnsECDsaP521()
    {
        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_EC, EcParamsP521);

        Assert.Equal(SigningAlgorithm.ECDsaP521, result);
    }

    [Fact]
    public void FromPkcs11KeyType_EcWithUnknownParams_ReturnsNull()
    {
        var unknownParams = new byte[] { 0x06, 0x03, 0x01, 0x02, 0x03 };

        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_EC, unknownParams);

        Assert.Null(result);
    }

    [Fact]
    public void FromPkcs11KeyType_EcWithNullParams_ReturnsNull()
    {
        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_EC, null);

        Assert.Null(result);
    }

    [Fact]
    public void FromPkcs11KeyType_Rsa_ReturnsRsa()
    {
        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_RSA, null);

        Assert.Equal(SigningAlgorithm.Rsa, result);
    }

    [Fact]
    public void FromPkcs11KeyType_UnsupportedKeyType_ReturnsNull()
    {
        var result = Pkcs11AlgorithmMap.FromPkcs11KeyType(CKK.CKK_AES, null);

        Assert.Null(result);
    }

    [Fact]
    public void ToSignMechanism_ECDsaP256_ReturnsEcdsaSha256()
    {
        var result = Pkcs11AlgorithmMap.ToSignMechanism(SigningAlgorithm.ECDsaP256);

        Assert.Equal(CKM.CKM_ECDSA_SHA256, result);
    }

    [Fact]
    public void ToSignMechanism_ECDsaP384_ReturnsEcdsaSha384()
    {
        var result = Pkcs11AlgorithmMap.ToSignMechanism(SigningAlgorithm.ECDsaP384);

        Assert.Equal(CKM.CKM_ECDSA_SHA384, result);
    }

    [Fact]
    public void ToSignMechanism_ECDsaP521_ReturnsEcdsaSha512()
    {
        var result = Pkcs11AlgorithmMap.ToSignMechanism(SigningAlgorithm.ECDsaP521);

        Assert.Equal(CKM.CKM_ECDSA_SHA512, result);
    }

    [Fact]
    public void ToSignMechanism_Rsa_ReturnsSha256RsaPkcssPss()
    {
        var result = Pkcs11AlgorithmMap.ToSignMechanism(SigningAlgorithm.Rsa);

        Assert.Equal(CKM.CKM_SHA256_RSA_PKCS_PSS, result);
    }

    [Fact]
    public void ToSignMechanism_Ed25519_ThrowsArgumentOutOfRange()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => Pkcs11AlgorithmMap.ToSignMechanism(SigningAlgorithm.Ed25519));

        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void ToSignMechanism_MLDsa65_ThrowsArgumentOutOfRange()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => Pkcs11AlgorithmMap.ToSignMechanism(SigningAlgorithm.MLDsa65));

        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void EcParamsP256_MatchesKnownOid()
    {
        Assert.Equal(10, Pkcs11AlgorithmMap.EcParamsP256.Length);
        Assert.Equal(0x06, Pkcs11AlgorithmMap.EcParamsP256[0]); // ASN.1 OID tag
    }

    [Fact]
    public void EcParamsP384_MatchesKnownOid()
    {
        Assert.Equal(7, Pkcs11AlgorithmMap.EcParamsP384.Length);
        Assert.Equal(0x06, Pkcs11AlgorithmMap.EcParamsP384[0]); // ASN.1 OID tag
    }

    [Fact]
    public void EcParamsP521_MatchesKnownOid()
    {
        Assert.Equal(7, Pkcs11AlgorithmMap.EcParamsP521.Length);
        Assert.Equal(0x06, Pkcs11AlgorithmMap.EcParamsP521[0]); // ASN.1 OID tag
    }
}
