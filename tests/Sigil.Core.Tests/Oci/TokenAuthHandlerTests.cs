using System.Net;
using System.Net.Http.Headers;
using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class TokenAuthHandlerTests : IDisposable
{
    private readonly MockTokenHandler _inner = new();
    private readonly TokenAuthHandler _handler;
    private readonly HttpClient _client;

    public TokenAuthHandlerTests()
    {
        _handler = new TokenAuthHandler(
            new RegistryCredentials { Username = "user", Password = "pass" },
            _inner);
        _client = new HttpClient(_handler);
    }

    public void Dispose()
    {
        _client.Dispose();
        _handler.Dispose();
    }

    [Fact]
    public async Task Non_401_passes_through()
    {
        _inner.SetResponse(HttpStatusCode.OK, "ok");

        var response = await _client.GetAsync("https://registry.test/v2/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, _inner.RequestCount);
    }

    [Fact]
    public async Task On_401_parses_challenge_and_retries()
    {
        _inner.SetChallengeResponse(
            realm: "https://auth.test/token",
            service: "registry.test",
            scope: "repository:repo:pull",
            tokenResponse: """{"token":"test-token"}""");

        var response = await _client.GetAsync("https://registry.test/v2/repo/manifests/latest");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // 1 = initial 401, 2 = token request, 3 = retry with token
        Assert.Equal(3, _inner.RequestCount);
    }

    [Fact]
    public async Task Sends_basic_auth_to_token_endpoint()
    {
        _inner.SetChallengeResponse(
            realm: "https://auth.test/token",
            service: "registry.test",
            scope: "repository:repo:pull",
            tokenResponse: """{"token":"test-token"}""");

        await _client.GetAsync("https://registry.test/v2/repo/manifests/latest");

        // Second request (token endpoint) should have Basic auth
        Assert.NotNull(_inner.TokenRequestAuthHeader);
        Assert.Equal("Basic", _inner.TokenRequestAuthHeader.Scheme);
    }

    [Fact]
    public async Task Retry_uses_bearer_token()
    {
        _inner.SetChallengeResponse(
            realm: "https://auth.test/token",
            service: "registry.test",
            scope: "repository:repo:pull",
            tokenResponse: """{"token":"my-token-123"}""");

        await _client.GetAsync("https://registry.test/v2/repo/manifests/latest");

        // Third request (retry) should have Bearer token
        Assert.NotNull(_inner.RetryAuthHeader);
        Assert.Equal("Bearer", _inner.RetryAuthHeader.Scheme);
        Assert.Equal("my-token-123", _inner.RetryAuthHeader.Parameter);
    }

    [Fact]
    public async Task Missing_www_authenticate_returns_401()
    {
        _inner.SetResponse(HttpStatusCode.Unauthorized, "no header");

        var response = await _client.GetAsync("https://registry.test/v2/");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, _inner.RequestCount);
    }

    [Fact]
    public async Task Token_endpoint_failure_returns_original_401()
    {
        _inner.SetChallengeResponse(
            realm: "https://auth.test/token",
            service: "registry.test",
            scope: "repository:repo:pull",
            tokenResponse: null); // token endpoint will return 500

        var response = await _client.GetAsync("https://registry.test/v2/repo/manifests/latest");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void ParseBearerChallenge_handles_quoted_values()
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(
            new AuthenticationHeaderValue("Bearer",
                "realm=\"https://auth.test/token\",service=\"myservice\",scope=\"repo:pull\""));

        var challenge = TokenAuthHandler.ParseBearerChallenge(response);

        Assert.NotNull(challenge);
        Assert.Equal("https://auth.test/token", challenge.Realm);
        Assert.Equal("myservice", challenge.Service);
        Assert.Equal("repo:pull", challenge.Scope);
    }

    [Fact]
    public void ParseBearerChallenge_handles_no_header()
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);

        var challenge = TokenAuthHandler.ParseBearerChallenge(response);

        Assert.Null(challenge);
    }

    [Fact]
    public async Task Access_token_field_supported()
    {
        _inner.SetChallengeResponse(
            realm: "https://auth.test/token",
            service: "registry.test",
            scope: "repository:repo:pull",
            tokenResponse: """{"access_token":"alt-token"}""");

        await _client.GetAsync("https://registry.test/v2/repo/manifests/latest");

        Assert.NotNull(_inner.RetryAuthHeader);
        Assert.Equal("alt-token", _inner.RetryAuthHeader.Parameter);
    }

    [Fact]
    public async Task Cached_token_used_on_subsequent_requests()
    {
        _inner.SetChallengeResponse(
            realm: "https://auth.test/token",
            service: "registry.test",
            scope: "repository:repo:pull",
            tokenResponse: """{"token":"cached-token"}""");

        // First request triggers auth flow (3 HTTP calls: 401 + token + retry)
        await _client.GetAsync("https://registry.test/v2/repo/manifests/latest");
        Assert.Equal(3, _inner.RequestCount);

        // Second request — should use cached token (only 1 HTTP call, no 401)
        // SetResponse changes mode but does NOT reset count
        _inner.SetSimpleResponse(HttpStatusCode.OK, "cached");
        await _client.GetAsync("https://registry.test/v2/repo/manifests/v2");

        // Total = 3 (auth flow) + 1 (cached) = 4
        Assert.Equal(4, _inner.RequestCount);
    }

    /// <summary>
    /// Mock handler that simulates 401 challenge + token endpoint + retry flow.
    /// </summary>
    private sealed class MockTokenHandler : HttpMessageHandler
    {
        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string _content = "";
        private string? _realm;
        private string? _service;
        private string? _scope;
        private string? _tokenResponse;
        private int _requestCount;

        public int RequestCount => _requestCount;
        public AuthenticationHeaderValue? TokenRequestAuthHeader { get; private set; }
        public AuthenticationHeaderValue? RetryAuthHeader { get; private set; }

        public void SetResponse(HttpStatusCode status, string content)
        {
            _statusCode = status;
            _content = content;
            _realm = null;
            _requestCount = 0;
        }

        public void SetSimpleResponse(HttpStatusCode status, string content)
        {
            _statusCode = status;
            _content = content;
            _realm = null;
            // Do NOT reset _requestCount — caller wants cumulative counting
        }

        public void SetChallengeResponse(string realm, string service, string scope, string? tokenResponse)
        {
            _realm = realm;
            _service = service;
            _scope = scope;
            _tokenResponse = tokenResponse;
            _requestCount = 0;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            _requestCount++;

            if (_realm is null)
            {
                // Simple response mode
                return Task.FromResult(new HttpResponseMessage(_statusCode)
                {
                    Content = new StringContent(_content)
                });
            }

            // Challenge mode
            if (_requestCount == 1)
            {
                // Initial request — return 401 with challenge
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Add(
                    new AuthenticationHeaderValue("Bearer",
                        $"""realm="{_realm}",service="{_service}",scope="{_scope}" """));
                return Task.FromResult(response);
            }

            if (request.RequestUri?.AbsoluteUri.StartsWith(_realm, StringComparison.Ordinal) == true)
            {
                // Token request
                TokenRequestAuthHeader = request.Headers.Authorization;

                if (_tokenResponse is null)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(_tokenResponse)
                });
            }

            // Retry with token
            RetryAuthHeader = request.Headers.Authorization;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("success")
            });
        }
    }
}
