using System.Text.Json;

namespace Sigil.Keyless;

public sealed class GitHubActionsOidcProvider : IOidcTokenProvider, IDisposable
{
    private const string RequestUrlEnvVar = "ACTIONS_ID_TOKEN_REQUEST_URL";
    private const string RequestTokenEnvVar = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

    private readonly string _requestUrl;
    private readonly string _requestToken;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    public string ProviderName => "GitHub Actions";

    public GitHubActionsOidcProvider()
        : this(
            Environment.GetEnvironmentVariable(RequestUrlEnvVar) ?? "",
            Environment.GetEnvironmentVariable(RequestTokenEnvVar) ?? "",
            new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
        _ownsClient = true;
    }

    public GitHubActionsOidcProvider(string requestUrl, string requestToken, HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _requestUrl = requestUrl;
        _requestToken = requestToken;
        _httpClient = httpClient;
        _ownsClient = false;
    }

    public async Task<KeylessResult<string>> AcquireTokenAsync(string audience, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        if (string.IsNullOrEmpty(_requestUrl) || string.IsNullOrEmpty(_requestToken))
        {
            return KeylessResult<string>.Fail(
                KeylessErrorKind.ConfigurationError,
                $"GitHub Actions OIDC environment variables ({RequestUrlEnvVar}, {RequestTokenEnvVar}) are not set.");
        }

        var url = $"{_requestUrl}&audience={Uri.EscapeDataString(audience)}";

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("bearer", _requestToken);

            using var response = await _httpClient.SendAsync(request, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return KeylessResult<string>.Fail(
                    KeylessErrorKind.TokenAcquisitionFailed,
                    $"GitHub Actions OIDC request returned HTTP {(int)response.StatusCode}.");
            }

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var doc = JsonDocument.Parse(json);

            if (!doc.RootElement.TryGetProperty("value", out var valueElement) ||
                valueElement.GetString() is not { Length: > 0 } token)
            {
                return KeylessResult<string>.Fail(
                    KeylessErrorKind.TokenAcquisitionFailed,
                    "GitHub Actions OIDC response missing 'value' field.");
            }

            return KeylessResult<string>.Ok(token);
        }
        catch (OperationCanceledException)
        {
            return KeylessResult<string>.Fail(
                KeylessErrorKind.NetworkError, "GitHub Actions OIDC request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return KeylessResult<string>.Fail(
                KeylessErrorKind.NetworkError, $"GitHub Actions OIDC request failed: {ex.Message}");
        }
        catch (JsonException)
        {
            return KeylessResult<string>.Fail(
                KeylessErrorKind.TokenAcquisitionFailed, "GitHub Actions OIDC response is not valid JSON.");
        }
    }

    public static bool IsAvailable()
    {
        return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(RequestUrlEnvVar)) &&
               !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(RequestTokenEnvVar));
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }
    }
}
