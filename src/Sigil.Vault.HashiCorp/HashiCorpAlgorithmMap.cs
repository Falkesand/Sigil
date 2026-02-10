using Sigil.Crypto;
using VaultSharp.V1.SecretsEngines.Transit;

namespace Sigil.Vault.HashiCorp;

internal static class HashiCorpAlgorithmMap
{
    // Map from Transit key type to SigningAlgorithm
    public static SigningAlgorithm? FromTransitKeyType(TransitKeyType transitKeyType) => transitKeyType switch
    {
        TransitKeyType.ecdsa_p256 => SigningAlgorithm.ECDsaP256,
        TransitKeyType.ecdsa_p384 => SigningAlgorithm.ECDsaP384,
        TransitKeyType.ecdsa_p521 => SigningAlgorithm.ECDsaP521,
        TransitKeyType.rsa_2048 or TransitKeyType.rsa_3072 or TransitKeyType.rsa_4096 => SigningAlgorithm.Rsa,
        _ => null
    };

    // Map from SigningAlgorithm to Transit hash algorithm
    public static TransitHashAlgorithm ToTransitHashAlgorithm(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ECDsaP256 => TransitHashAlgorithm.SHA2_256,
        SigningAlgorithm.ECDsaP384 => TransitHashAlgorithm.SHA2_384,
        SigningAlgorithm.ECDsaP521 => TransitHashAlgorithm.SHA2_512,
        SigningAlgorithm.Rsa => TransitHashAlgorithm.SHA2_256,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported algorithm for Transit.")
    };

    // Map from SigningAlgorithm to Transit signature algorithm
    public static SignatureAlgorithm? ToTransitSignatureAlgorithm(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.Rsa => SignatureAlgorithm.pss,
        _ => null  // EC types don't need this parameter
    };
}
