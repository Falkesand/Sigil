namespace Sigil.Keyless;

public sealed class ManualOidcTokenProvider : IOidcTokenProvider
{
    private readonly string _token;

    public string ProviderName => "Manual";

    public ManualOidcTokenProvider(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        _token = token;
    }

    public Task<KeylessResult<string>> AcquireTokenAsync(string audience, CancellationToken ct = default)
    {
        return Task.FromResult(KeylessResult<string>.Ok(_token));
    }
}
