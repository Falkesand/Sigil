namespace Sigil.Crypto;

/// <summary>
/// Holds factory delegates for a cryptographic provider registered via <see cref="CryptoProviderRegistry"/>.
/// External assemblies (e.g. Sigil.Crypto.BouncyCastle) create instances of this class
/// and register them so that <see cref="SignerFactory"/> and <see cref="VerifierFactory"/>
/// can delegate to external implementations transparently.
/// </summary>
public sealed class CryptoProviderRegistration
{
    /// <summary>Generates a new key pair and returns a signer.</summary>
    public required Func<ISigner> Generate { get; init; }

    /// <summary>Creates a signer from DER-encoded PKCS#8 private key bytes.</summary>
    public required Func<byte[], ISigner> FromPkcs8 { get; init; }

    /// <summary>Creates a signer from a PEM-encoded private key (unencrypted or encrypted).</summary>
    public required Func<ReadOnlyMemory<char>, ReadOnlyMemory<char>, ISigner> FromPem { get; init; }

    /// <summary>Creates a verifier from DER-encoded SPKI public key bytes.</summary>
    public required Func<byte[], IVerifier> FromSpki { get; init; }
}
