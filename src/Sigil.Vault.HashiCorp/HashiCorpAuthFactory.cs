using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.AppRole;
using VaultSharp.V1.AuthMethods.Token;

namespace Sigil.Vault.HashiCorp;

internal static class HashiCorpAuthFactory
{
    public static VaultResult<IVaultClient> CreateClient()
    {
        var vaultAddr = Environment.GetEnvironmentVariable("VAULT_ADDR");
        if (string.IsNullOrWhiteSpace(vaultAddr))
            return VaultResult<IVaultClient>.Fail(VaultErrorKind.ConfigurationError, "VAULT_ADDR environment variable is not set.");

        if (!Uri.TryCreate(vaultAddr, UriKind.Absolute, out var vaultUri))
            return VaultResult<IVaultClient>.Fail(VaultErrorKind.ConfigurationError, $"VAULT_ADDR is not a valid URI: {vaultAddr}");

        // Enforce HTTPS except for localhost
        if (vaultUri.Scheme != "https" && !IsLocalhost(vaultUri))
            return VaultResult<IVaultClient>.Fail(VaultErrorKind.ConfigurationError, "VAULT_ADDR must use HTTPS (except localhost).");

        var authResult = ResolveAuthMethod();
        if (!authResult.IsSuccess)
            return VaultResult<IVaultClient>.Fail(authResult.ErrorKind, authResult.ErrorMessage);

        var settings = new VaultClientSettings(vaultAddr, authResult.Value)
        {
            MyHttpClientProviderFunc = handler => new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            }
        };

        var ns = Environment.GetEnvironmentVariable("VAULT_NAMESPACE");
        if (!string.IsNullOrWhiteSpace(ns))
            settings.Namespace = ns;

        return VaultResult<IVaultClient>.Ok(new VaultClient(settings));
    }

    public static string GetMountPath() =>
        Environment.GetEnvironmentVariable("VAULT_MOUNT_PATH") ?? "transit";

    private static VaultResult<IAuthMethodInfo> ResolveAuthMethod()
    {
        // Priority 1: VAULT_TOKEN
        var token = Environment.GetEnvironmentVariable("VAULT_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
            return VaultResult<IAuthMethodInfo>.Ok(new TokenAuthMethodInfo(token));

        // Priority 2: AppRole
        var roleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
        var secretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
        if (!string.IsNullOrWhiteSpace(roleId) && !string.IsNullOrWhiteSpace(secretId))
            return VaultResult<IAuthMethodInfo>.Ok(new AppRoleAuthMethodInfo(roleId, secretId));

        // Priority 3: ~/.vault-token file
        var tokenFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".vault-token");
        if (File.Exists(tokenFilePath))
        {
            var fileToken = File.ReadAllText(tokenFilePath).Trim();
            if (!string.IsNullOrWhiteSpace(fileToken))
                return VaultResult<IAuthMethodInfo>.Ok(new TokenAuthMethodInfo(fileToken));
        }

        return VaultResult<IAuthMethodInfo>.Fail(VaultErrorKind.AuthenticationFailed,
            "No Vault credentials found. Set VAULT_TOKEN, VAULT_ROLE_ID+VAULT_SECRET_ID, or create ~/.vault-token.");
    }

    private static bool IsLocalhost(Uri uri) =>
        uri.Host is "localhost" or "127.0.0.1" or "::1";
}
