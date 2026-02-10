namespace Sigil.Keyless;

public static class OidcTokenProviderFactory
{
    public static KeylessResult<IOidcTokenProvider> Create(string? manualToken = null)
    {
        if (!string.IsNullOrWhiteSpace(manualToken))
        {
            return KeylessResult<IOidcTokenProvider>.Ok(new ManualOidcTokenProvider(manualToken));
        }

        if (GitHubActionsOidcProvider.IsAvailable())
        {
            return KeylessResult<IOidcTokenProvider>.Ok(new GitHubActionsOidcProvider());
        }

        return KeylessResult<IOidcTokenProvider>.Fail(
            KeylessErrorKind.ConfigurationError,
            "No OIDC provider available. Use --oidc-token or run in a supported CI environment (GitHub Actions).");
    }
}
