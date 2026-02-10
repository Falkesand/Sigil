using System.Text.Json;

namespace Sigil.Keyless;

public sealed class JwksClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    public JwksClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
        _ownsClient = false;
    }

    public JwksClient() : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
        _ownsClient = true;
    }

    public async Task<KeylessResult<JsonElement>> FetchJwksAsync(
        string issuerUrl, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUrl);

        // Build OpenID configuration URL
        var configUrl = issuerUrl.TrimEnd('/') + "/.well-known/openid-configuration";

        if (!Uri.TryCreate(configUrl, UriKind.Absolute, out var configUri))
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.JwksFetchFailed, $"Invalid issuer URL: {issuerUrl}");
        }

        // Enforce HTTPS except localhost
        if (configUri.Scheme != "https" && !IsLocalhost(configUri))
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.JwksFetchFailed, "HTTPS is required for non-localhost URLs.");
        }

        // Step 1: Fetch OpenID configuration
        string jwksUri;
        try
        {
            using var configResponse = await _httpClient.GetAsync(configUri, ct).ConfigureAwait(false);
            if (!configResponse.IsSuccessStatusCode)
            {
                return KeylessResult<JsonElement>.Fail(
                    KeylessErrorKind.JwksFetchFailed,
                    $"OpenID configuration request returned HTTP {(int)configResponse.StatusCode}.");
            }

            var configJson = await configResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var configDoc = JsonDocument.Parse(configJson);

            if (!configDoc.RootElement.TryGetProperty("jwks_uri", out var jwksUriElement) ||
                jwksUriElement.GetString() is not { } uri)
            {
                return KeylessResult<JsonElement>.Fail(
                    KeylessErrorKind.JwksFetchFailed, "OpenID configuration missing 'jwks_uri'.");
            }

            jwksUri = uri;
        }
        catch (OperationCanceledException)
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.NetworkError, "OpenID configuration request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.NetworkError, $"OpenID configuration request failed: {ex.Message}");
        }
        catch (JsonException)
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.JwksFetchFailed, "OpenID configuration is not valid JSON.");
        }

        // Validate jwks_uri scheme — SSRF mitigation for untrusted OIDC config responses
        if (!Uri.TryCreate(jwksUri, UriKind.Absolute, out var jwksUriParsed))
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.JwksFetchFailed, $"Invalid jwks_uri: {jwksUri}");
        }

        if (jwksUriParsed.Scheme != "https" && !IsLocalhost(jwksUriParsed))
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.JwksFetchFailed, "HTTPS is required for JWKS endpoint.");
        }

        // Step 2: Fetch JWKS
        try
        {
            using var jwksResponse = await _httpClient.GetAsync(jwksUri, ct).ConfigureAwait(false);
            if (!jwksResponse.IsSuccessStatusCode)
            {
                return KeylessResult<JsonElement>.Fail(
                    KeylessErrorKind.JwksFetchFailed,
                    $"JWKS request returned HTTP {(int)jwksResponse.StatusCode}.");
            }

            var jwksJson = await jwksResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var jwksDoc = JsonDocument.Parse(jwksJson);

            if (!jwksDoc.RootElement.TryGetProperty("keys", out var keys))
            {
                return KeylessResult<JsonElement>.Fail(
                    KeylessErrorKind.JwksFetchFailed, "JWKS response missing 'keys' array.");
            }

            return KeylessResult<JsonElement>.Ok(keys.Clone());
        }
        catch (OperationCanceledException)
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.NetworkError, "JWKS request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.NetworkError, $"JWKS request failed: {ex.Message}");
        }
        catch (JsonException)
        {
            return KeylessResult<JsonElement>.Fail(
                KeylessErrorKind.JwksFetchFailed, "JWKS response is not valid JSON.");
        }
    }

    private static bool IsLocalhost(Uri uri)
    {
        return string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) ||
               uri.Host == "127.0.0.1" ||
               uri.Host == "::1";
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }
    }
}
