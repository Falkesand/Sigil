using System;
using Azure.Identity;
using Sigil.Vault;

namespace Sigil.Vault.Azure;

/// <summary>
/// Factory for creating Azure Key Vault authentication credentials and vault URIs.
/// </summary>
internal static class AzureAuthFactory
{
    private const string VaultUrlEnvironmentVariable = "AZURE_KEY_VAULT_URL";

    /// <summary>
    /// Creates a vault URI and credential from the environment.
    /// </summary>
    /// <returns>
    /// A <see cref="VaultResult{T}"/> containing the vault URI and credential, or an error.
    /// </returns>
    public static VaultResult<(Uri VaultUri, DefaultAzureCredential Credential)> CreateFromEnvironment()
    {
        var vaultUrlString = Environment.GetEnvironmentVariable(VaultUrlEnvironmentVariable);

        if (string.IsNullOrWhiteSpace(vaultUrlString))
        {
            return VaultResult<(Uri, DefaultAzureCredential)>.Fail(
                VaultErrorKind.ConfigurationError,
                $"Environment variable '{VaultUrlEnvironmentVariable}' is not set or empty.");
        }

        if (!Uri.TryCreate(vaultUrlString, UriKind.Absolute, out var vaultUri))
        {
            return VaultResult<(Uri, DefaultAzureCredential)>.Fail(
                VaultErrorKind.ConfigurationError,
                $"Invalid vault URL in '{VaultUrlEnvironmentVariable}': {vaultUrlString}");
        }

        // Validate HTTPS (except localhost for development)
        if (!vaultUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            var isLocalhost = vaultUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || vaultUri.Host.Equals("127.0.0.1", StringComparison.Ordinal)
                || vaultUri.Host.Equals("[::1]", StringComparison.Ordinal);

            if (!isLocalhost)
            {
                return VaultResult<(Uri, DefaultAzureCredential)>.Fail(
                    VaultErrorKind.ConfigurationError,
                    $"Vault URL must use HTTPS (except localhost): {vaultUri}");
            }
        }

        var credential = new DefaultAzureCredential();

        return VaultResult<(Uri, DefaultAzureCredential)>.Ok((vaultUri, credential));
    }
}
