using System.Diagnostics.CodeAnalysis;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Sigil.Crypto;

namespace Sigil.Vault.Azure;

/// <summary>
/// Maps between Sigil <see cref="SigningAlgorithm"/> and Azure Key Vault algorithm types.
/// </summary>
internal static class AzureAlgorithmMap
{
    /// <summary>
    /// Maps a Sigil <see cref="SigningAlgorithm"/> to an Azure <see cref="SignatureAlgorithm"/>.
    /// </summary>
    /// <param name="algorithm">The Sigil signing algorithm.</param>
    /// <param name="azureAlgorithm">The corresponding Azure signature algorithm.</param>
    /// <returns>True if the mapping is supported; otherwise, false.</returns>
    public static bool TryGetAzureAlgorithm(
        SigningAlgorithm algorithm,
        [NotNullWhen(true)] out SignatureAlgorithm? azureAlgorithm)
    {
        switch (algorithm)
        {
            case SigningAlgorithm.ECDsaP256:
                azureAlgorithm = SignatureAlgorithm.ES256;
                return true;
            case SigningAlgorithm.ECDsaP384:
                azureAlgorithm = SignatureAlgorithm.ES384;
                return true;
            case SigningAlgorithm.Rsa:
                azureAlgorithm = SignatureAlgorithm.PS256;
                return true;
            default:
                azureAlgorithm = null;
                return false;
        }
    }

    /// <summary>
    /// Maps an Azure <see cref="KeyType"/> and curve name to a Sigil <see cref="SigningAlgorithm"/>.
    /// </summary>
    /// <param name="keyType">The Azure key type.</param>
    /// <param name="curveName">The curve name for EC keys.</param>
    /// <param name="algorithm">The corresponding Sigil signing algorithm.</param>
    /// <returns>True if the mapping is supported; otherwise, false.</returns>
    public static bool TryGetSigningAlgorithm(
        KeyType keyType,
        KeyCurveName? curveName,
        out SigningAlgorithm algorithm)
    {
        if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            switch (curveName?.ToString())
            {
                case "P-256":
                    algorithm = SigningAlgorithm.ECDsaP256;
                    return true;
                case "P-384":
                    algorithm = SigningAlgorithm.ECDsaP384;
                    return true;
                default:
                    algorithm = default;
                    return false;
            }
        }

        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            algorithm = SigningAlgorithm.Rsa;
            return true;
        }

        algorithm = default;
        return false;
    }
}
