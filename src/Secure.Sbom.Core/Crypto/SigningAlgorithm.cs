namespace Secure.Sbom.Crypto;

public enum SigningAlgorithm
{
    ECDsaP256
}

public static class SigningAlgorithmExtensions
{
    public static string ToCanonicalName(this SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ECDsaP256 => "ecdsa-p256",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    public static SigningAlgorithm ParseAlgorithm(string name) => name.ToLowerInvariant() switch
    {
        "ecdsa-p256" => SigningAlgorithm.ECDsaP256,
        _ => throw new ArgumentException($"Unknown algorithm: {name}", nameof(name))
    };
}
