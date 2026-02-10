using Amazon.KeyManagementService;
using Sigil.Crypto;

namespace Sigil.Vault.Aws;

internal static class AwsAlgorithmMap
{
    public static SigningAlgorithmSpec ToAwsAlgorithm(SigningAlgorithm algorithm)
    {
        return algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => SigningAlgorithmSpec.ECDSA_SHA_256,
            SigningAlgorithm.ECDsaP384 => SigningAlgorithmSpec.ECDSA_SHA_384,
            SigningAlgorithm.ECDsaP521 => SigningAlgorithmSpec.ECDSA_SHA_512,
            SigningAlgorithm.Rsa => SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
            _ => throw new ArgumentException($"Unsupported signing algorithm: {algorithm}", nameof(algorithm))
        };
    }

    public static SigningAlgorithm FromAwsKeySpec(KeySpec keySpec)
    {
        if (keySpec == KeySpec.ECC_NIST_P256)
        {
            return SigningAlgorithm.ECDsaP256;
        }
        if (keySpec == KeySpec.ECC_NIST_P384)
        {
            return SigningAlgorithm.ECDsaP384;
        }
        if (keySpec == KeySpec.ECC_NIST_P521)
        {
            return SigningAlgorithm.ECDsaP521;
        }
        if (keySpec == KeySpec.RSA_2048 || keySpec == KeySpec.RSA_3072 || keySpec == KeySpec.RSA_4096)
        {
            return SigningAlgorithm.Rsa;
        }

        throw new ArgumentException($"Unsupported AWS key spec: {keySpec}", nameof(keySpec));
    }
}
