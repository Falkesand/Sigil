namespace Sigil.Crypto;

public enum SigningAlgorithm
{
    ECDsaP256,
    ECDsaP384,
    ECDsaP521,
    Ed25519,
    Rsa,
    MLDsa65,
    Ed448
}

public static class SigningAlgorithmExtensions
{
    public static string ToCanonicalName(this SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ECDsaP256 => "ecdsa-p256",
        SigningAlgorithm.ECDsaP384 => "ecdsa-p384",
        SigningAlgorithm.ECDsaP521 => "ecdsa-p521",
        SigningAlgorithm.Ed25519 => "ed25519",
        SigningAlgorithm.Rsa => "rsa-pss-sha256",
        SigningAlgorithm.MLDsa65 => "ml-dsa-65",
        SigningAlgorithm.Ed448 => "ed448",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    public static SigningAlgorithm ParseAlgorithm(string name) => name.ToLowerInvariant() switch
    {
        "ecdsa-p256" => SigningAlgorithm.ECDsaP256,
        "ecdsa-p384" => SigningAlgorithm.ECDsaP384,
        "ecdsa-p521" => SigningAlgorithm.ECDsaP521,
        "ed25519" => SigningAlgorithm.Ed25519,
        "rsa-pss-sha256" => SigningAlgorithm.Rsa,
        "ml-dsa-65" => SigningAlgorithm.MLDsa65,
        "ed448" => SigningAlgorithm.Ed448,
        _ => throw new ArgumentException($"Unknown algorithm: {name}", nameof(name))
    };
}
