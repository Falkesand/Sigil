using Google.Cloud.Kms.V1;
using Sigil.Crypto;

namespace Sigil.Vault.Gcp;

internal static class GcpAlgorithmMap
{
    public static CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm ToGcpAlgorithm(SigningAlgorithm algorithm)
    {
        return algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256,
            SigningAlgorithm.ECDsaP384 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384,
            SigningAlgorithm.Rsa => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss2048Sha256,
            SigningAlgorithm.Ed25519 => throw new NotSupportedException("Ed25519 is not supported by Google Cloud KMS"),
            SigningAlgorithm.MLDsa65 => throw new NotSupportedException("ML-DSA-65 is not supported by Google Cloud KMS"),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported signing algorithm")
        };
    }

    public static VaultResult<SigningAlgorithm> FromGcpAlgorithm(CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm gcpAlgorithm)
    {
        return gcpAlgorithm switch
        {
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256 => VaultResult<SigningAlgorithm>.Ok(SigningAlgorithm.ECDsaP256),
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384 => VaultResult<SigningAlgorithm>.Ok(SigningAlgorithm.ECDsaP384),
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss2048Sha256 => VaultResult<SigningAlgorithm>.Ok(SigningAlgorithm.Rsa),
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss3072Sha256 => VaultResult<SigningAlgorithm>.Ok(SigningAlgorithm.Rsa),
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss4096Sha256 => VaultResult<SigningAlgorithm>.Ok(SigningAlgorithm.Rsa),
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPss4096Sha512 => VaultResult<SigningAlgorithm>.Ok(SigningAlgorithm.Rsa),
            _ => VaultResult<SigningAlgorithm>.Fail(VaultErrorKind.UnsupportedAlgorithm, $"GCP algorithm {gcpAlgorithm} is not supported")
        };
    }
}
