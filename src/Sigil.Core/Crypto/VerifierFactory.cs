namespace Sigil.Crypto;

/// <summary>
/// Factory for creating verifiers from embedded public keys and algorithm names.
/// </summary>
public static class VerifierFactory
{
    /// <summary>
    /// Creates a verifier from SPKI bytes and the canonical algorithm name from the envelope.
    /// </summary>
    public static IVerifier CreateFromPublicKey(byte[] spki, string algorithmName)
    {
        ArgumentNullException.ThrowIfNull(spki);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);

        var algorithm = SigningAlgorithmExtensions.ParseAlgorithm(algorithmName);

        return algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => ECDsaP256Verifier.FromPublicKey(spki),
            SigningAlgorithm.ECDsaP384 => ECDsaP384Verifier.FromPublicKey(spki),
            SigningAlgorithm.Rsa => RsaVerifier.FromPublicKey(spki),
            SigningAlgorithm.Ed25519 => throw new NotSupportedException(
                "Ed25519 is not yet available in this .NET SDK. It will be supported in a future release."),
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithmName}")
        };
    }
}
