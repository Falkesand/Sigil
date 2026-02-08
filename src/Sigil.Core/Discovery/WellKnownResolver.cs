namespace Sigil.Discovery;

/// <summary>
/// Resolves trust bundles from well-known HTTPS URLs.
/// Fetches https://domain/.well-known/sigil/trust.json.
/// </summary>
public sealed class WellKnownResolver : IDiscoveryResolver
{
    private const string WellKnownPath = "/.well-known/sigil/trust.json";

    private readonly HttpClient _httpClient;

    public WellKnownResolver(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public WellKnownResolver() : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
    }

    public async Task<DiscoveryResult<string>> ResolveAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        Uri uri;
        try
        {
            uri = BuildUri(identifier);
        }
        catch (UriFormatException ex)
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.InvalidUri, ex.Message);
        }

        // Enforce HTTPS unless localhost
        if (uri.Scheme == "http" && !IsLocalhost(uri))
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.InvalidUri,
                "HTTPS is required for non-localhost URLs.");
        }

        try
        {
            using var response = await _httpClient.GetAsync(uri, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return DiscoveryResult<string>.Fail(DiscoveryErrorKind.NotFound,
                    $"No trust bundle found at {uri}");
            }

            if (!response.IsSuccessStatusCode)
            {
                return DiscoveryResult<string>.Fail(DiscoveryErrorKind.NetworkError,
                    $"HTTP {(int)response.StatusCode} from {uri}");
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return DiscoveryResult<string>.Ok(content);
        }
        catch (OperationCanceledException)
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.Timeout,
                $"Request to {uri} was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.NetworkError,
                $"HTTP request failed: {ex.Message}");
        }
    }

    private static Uri BuildUri(string identifier)
    {
        // If it already looks like a full URL, use it directly
        if (Uri.TryCreate(identifier, UriKind.Absolute, out var existingUri) &&
            (existingUri.Scheme == "https" || existingUri.Scheme == "http"))
        {
            return existingUri;
        }

        // Otherwise treat as domain name and construct well-known URL
        return new Uri($"https://{identifier}{WellKnownPath}");
    }

    private static bool IsLocalhost(Uri uri)
    {
        return string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) ||
               uri.Host == "127.0.0.1" ||
               uri.Host == "::1";
    }
}
