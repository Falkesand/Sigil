using Sigil.Crypto;

namespace Sigil.Crypto.BouncyCastle;

/// <summary>
/// Registers BouncyCastle-backed cryptographic providers for Ed25519 and Ed448.
/// Call <see cref="Register"/> at application startup to make these algorithms available.
/// </summary>
public static class BouncyCastleCryptoProvider
{
    /// <summary>
    /// Registers Ed25519 and Ed448 providers with the global <see cref="CryptoProviderRegistry"/>.
    /// Safe to call multiple times — subsequent calls are no-ops.
    /// </summary>
    public static void Register()
    {
        RegisterAlgorithm(SigningAlgorithm.Ed25519, new CryptoProviderRegistration
        {
            Generate = Ed25519BouncyCastleSigner.Generate,
            FromPkcs8 = Ed25519BouncyCastleSigner.FromPkcs8,
            FromPem = (pem, passphrase) => Ed25519BouncyCastleSigner.FromPem(pem, passphrase),
            FromSpki = Ed25519BouncyCastleVerifier.FromPublicKey,
        });

        RegisterAlgorithm(SigningAlgorithm.Ed448, new CryptoProviderRegistration
        {
            Generate = Ed448BouncyCastleSigner.Generate,
            FromPkcs8 = Ed448BouncyCastleSigner.FromPkcs8,
            FromPem = (pem, passphrase) => Ed448BouncyCastleSigner.FromPem(pem, passphrase),
            FromSpki = Ed448BouncyCastleVerifier.FromPublicKey,
        });
    }

    private static void RegisterAlgorithm(SigningAlgorithm algorithm, CryptoProviderRegistration registration)
    {
        try
        {
            CryptoProviderRegistry.Register(algorithm, registration);
        }
        catch (InvalidOperationException)
        {
            // Already registered — idempotent
        }
    }
}
