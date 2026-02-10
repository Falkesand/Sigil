namespace Sigil.Keyless;

public interface IOidcTokenProvider
{
    string ProviderName { get; }
    Task<KeylessResult<string>> AcquireTokenAsync(string audience, CancellationToken ct = default);
}
