using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace Sigil.Crypto;

/// <summary>
/// Thread-safe registry for external cryptographic providers. Factories consult this registry
/// before falling back to built-in implementations. External assemblies call <see cref="Register"/>
/// at startup to make their algorithms available.
/// </summary>
public static class CryptoProviderRegistry
{
    private static readonly ConcurrentDictionary<SigningAlgorithm, CryptoProviderRegistration> Providers = new();

    /// <summary>
    /// Registers a cryptographic provider for the specified algorithm.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if a provider is already registered for this algorithm.</exception>
    public static void Register(SigningAlgorithm algorithm, CryptoProviderRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        if (!Providers.TryAdd(algorithm, registration))
            throw new InvalidOperationException(
                $"A cryptographic provider is already registered for {algorithm.ToCanonicalName()}.");
    }

    /// <summary>
    /// Attempts to retrieve a registered provider for the specified algorithm.
    /// </summary>
    public static bool TryGet(SigningAlgorithm algorithm, [MaybeNullWhen(false)] out CryptoProviderRegistration registration)
        => Providers.TryGetValue(algorithm, out registration);

    /// <summary>
    /// Clears all registered providers. For testing only.
    /// </summary>
    internal static void Reset() => Providers.Clear();
}
