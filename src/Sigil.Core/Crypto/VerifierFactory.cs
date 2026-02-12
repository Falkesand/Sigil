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

        if (CryptoProviderRegistry.TryGet(algorithm, out var provider))
            return provider.FromSpki(spki);

        return algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => ECDsaP256Verifier.FromPublicKey(spki),
            SigningAlgorithm.ECDsaP384 => ECDsaP384Verifier.FromPublicKey(spki),
            SigningAlgorithm.ECDsaP521 => ECDsaP521Verifier.FromPublicKey(spki),
            SigningAlgorithm.Rsa => RsaVerifier.FromPublicKey(spki),
            SigningAlgorithm.Ed25519 => throw new NotSupportedException(
                "Ed25519 requires a registered cryptographic provider. Call BouncyCastleCryptoProvider.Register() or install the Sigil.Crypto.BouncyCastle package."),
            SigningAlgorithm.MLDsa65 => MLDsa65Verifier.FromPublicKey(spki),
            SigningAlgorithm.Ed448 => throw new NotSupportedException(
                "Ed448 requires a registered cryptographic provider. Call BouncyCastleCryptoProvider.Register() or install the Sigil.Crypto.BouncyCastle package."),
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithmName}")
        };
    }
}
