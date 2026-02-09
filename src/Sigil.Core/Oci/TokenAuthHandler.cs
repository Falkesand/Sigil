using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Sigil.Oci;

/// <summary>
/// DelegatingHandler that intercepts 401 responses, requests a Bearer token,
/// and retries with the token. Caches tokens per (registry, scope).
/// </summary>
public sealed class TokenAuthHandler : DelegatingHandler
{
    private readonly ConcurrentDictionary<string, CachedToken> _tokenCache = new();
    private readonly RegistryCredentials? _credentials;

    public TokenAuthHandler(RegistryCredentials? credentials, HttpMessageHandler? innerHandler = null)
        : base(innerHandler ?? new HttpClientHandler())
    {
        _credentials = credentials;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Try cached token first
        var cacheKey = BuildCacheKey(request.RequestUri);
        if (cacheKey is not null && _tokenCache.TryGetValue(cacheKey, out var cached) && !cached.IsExpired)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cached.Token);
        }

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Unauthorized)
            return response;

        // Parse Www-Authenticate header
        var challenge = ParseBearerChallenge(response);
        if (challenge is null)
            return response;

        // Request token
        var token = await RequestTokenAsync(challenge, cancellationToken).ConfigureAwait(false);
        if (token is null)
            return response;

        // Cache token per (registry, scope) and also as registry-wide fallback
        if (cacheKey is not null)
        {
            var expiry = DateTimeOffset.UtcNow.AddSeconds(ExpiresInSeconds);
            var scopeCacheKey = $"{cacheKey}:{challenge.Scope ?? "default"}";
            _tokenCache[scopeCacheKey] = new CachedToken(token, expiry);
            _tokenCache[cacheKey] = new CachedToken(token, expiry);
        }

        // Retry with token
        response.Dispose();
        var retryRequest = await CloneRequestAsync(request).ConfigureAwait(false);
        retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(retryRequest, cancellationToken).ConfigureAwait(false);
    }

    internal static BearerChallenge? ParseBearerChallenge(HttpResponseMessage response)
    {
        if (response.Headers.WwwAuthenticate.Count == 0)
            return null;

        foreach (var auth in response.Headers.WwwAuthenticate)
        {
            if (!string.Equals(auth.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
                continue;

            if (auth.Parameter is null)
                continue;

            var realm = ExtractParam(auth.Parameter, "realm");
            var service = ExtractParam(auth.Parameter, "service");
            var scope = ExtractParam(auth.Parameter, "scope");

            if (realm is null)
                continue;

            return new BearerChallenge(realm, service, scope);
        }

        return null;
    }

    private static string? ExtractParam(string header, string name)
    {
        var key = $"{name}=";
        var start = header.IndexOf(key, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
            return null;

        start += key.Length;

        // Handle quoted value
        if (start < header.Length && header[start] == '"')
        {
            start++;
            var end = header.IndexOf('"', start);
            return end < 0 ? header[start..] : header[start..end];
        }

        // Unquoted value — ends at comma or end of string
        var commaIndex = header.IndexOf(',', start);
        return commaIndex < 0 ? header[start..] : header[start..commaIndex];
    }

    private async Task<string?> RequestTokenAsync(BearerChallenge challenge, CancellationToken ct)
    {
        // Validate realm URL to prevent SSRF — a malicious registry could point
        // the realm to an internal network address and steal Basic auth credentials.
        if (!Uri.TryCreate(challenge.Realm, UriKind.Absolute, out var realmUri))
            return null;

        if (!string.Equals(realmUri.Scheme, "https", StringComparison.OrdinalIgnoreCase) &&
            !IsLoopback(realmUri.Host))
            return null;

        var uri = challenge.Realm;
        var separator = uri.Contains('?') ? '&' : '?';
        if (challenge.Service is not null)
            uri = $"{uri}{separator}service={Uri.EscapeDataString(challenge.Service)}";
        separator = uri.Contains('?') ? '&' : '?';
        if (challenge.Scope is not null)
            uri = $"{uri}{separator}scope={Uri.EscapeDataString(challenge.Scope)}";

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Get, uri);

        // Add Basic auth if we have credentials
        if (_credentials is not null && !_credentials.IsAnonymous && _credentials.Username is not null)
        {
            tokenRequest.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", _credentials.ToBasicHeaderValue());
        }

        var tokenResponse = await base.SendAsync(tokenRequest, ct).ConfigureAwait(false);
        if (!tokenResponse.IsSuccessStatusCode)
            return null;

        var json = await tokenResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        try
        {
            using var doc = JsonDocument.Parse(json);
            string? token = null;
            if (doc.RootElement.TryGetProperty("token", out var tokenProp))
                token = tokenProp.GetString();
            else if (doc.RootElement.TryGetProperty("access_token", out var accessProp))
                token = accessProp.GetString();

            if (token is not null)
            {
                // Parse expires_in if available, default to 300s (5 minutes)
                var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var expProp)
                    && expProp.TryGetInt32(out var expVal)
                    ? expVal
                    : 300;
                // Cache with safety margin (subtract 60s, minimum 30s)
                ExpiresInSeconds = Math.Max(expiresIn - 60, 30);
            }

            return token;
        }
        catch (JsonException)
        {
            // Fall through
        }

        return null;
    }

    /// <summary>Parsed token expiry in seconds (with safety margin). Set by RequestTokenAsync.</summary>
    private int ExpiresInSeconds { get; set; } = 240; // default 4 minutes

    private static string? BuildCacheKey(Uri? uri) =>
        uri is null ? null : $"{uri.Scheme}://{uri.Authority}";

    private static bool IsLoopback(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(host, "127.0.0.1", StringComparison.Ordinal) ||
        string.Equals(host, "::1", StringComparison.Ordinal);

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);

        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        if (original.Content is not null)
        {
            var content = await original.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            clone.Content = new ByteArrayContent(content);
            foreach (var header in original.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }

    internal sealed record BearerChallenge(string Realm, string? Service, string? Scope);

    private sealed record CachedToken(string Token, DateTimeOffset ExpiresAt)
    {
        public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
    }
}
