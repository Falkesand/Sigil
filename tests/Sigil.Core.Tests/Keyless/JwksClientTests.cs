using System.Net;
using System.Text;
using System.Text.Json;
using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class JwksClientTests : IDisposable
{
    private HttpClient? _httpClient;
    private JwksClient? _jwksClient;

    [Fact]
    public async Task FetchJwksAsync_Success_ReturnsKeys()
    {
        var configJson = JsonSerializer.Serialize(new
        {
            issuer = "https://test.example.com",
            jwks_uri = "https://test.example.com/.well-known/jwks.json"
        });
        var jwksJson = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", kid = "k1", alg = "RS256", n = "abc", e = "AQAB" }
            }
        });

        CreateClient(new MockHandler(configJson, jwksJson));

        var result = await _jwksClient!.FetchJwksAsync("https://test.example.com");

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value.GetArrayLength());
    }

    [Fact]
    public async Task FetchJwksAsync_ConfigNotFound_Fails()
    {
        CreateClient(new MockHandler(HttpStatusCode.NotFound));

        var result = await _jwksClient!.FetchJwksAsync("https://test.example.com");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.JwksFetchFailed, result.ErrorKind);
    }

    [Fact]
    public async Task FetchJwksAsync_MissingJwksUri_Fails()
    {
        var configJson = JsonSerializer.Serialize(new { issuer = "https://test.example.com" });
        CreateClient(new MockHandler(configJson, "{}"));

        var result = await _jwksClient!.FetchJwksAsync("https://test.example.com");

        Assert.False(result.IsSuccess);
        Assert.Contains("jwks_uri", result.ErrorMessage);
    }

    [Fact]
    public async Task FetchJwksAsync_JwksFetchFailure_Fails()
    {
        var configJson = JsonSerializer.Serialize(new
        {
            issuer = "https://test.example.com",
            jwks_uri = "https://test.example.com/.well-known/jwks.json"
        });

        CreateClient(new MockHandler(configJson, null, HttpStatusCode.InternalServerError));

        var result = await _jwksClient!.FetchJwksAsync("https://test.example.com");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.JwksFetchFailed, result.ErrorKind);
    }

    [Fact]
    public async Task FetchJwksAsync_HttpWithoutLocalhost_Fails()
    {
        CreateClient(new MockHandler("{}", "{}"));

        var result = await _jwksClient!.FetchJwksAsync("http://remote.example.com");

        Assert.False(result.IsSuccess);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public async Task FetchJwksAsync_JwksUriHttpNonLocalhost_Fails()
    {
        // SSRF mitigation: jwks_uri from untrusted OIDC config must also be HTTPS
        var configJson = JsonSerializer.Serialize(new
        {
            issuer = "https://test.example.com",
            jwks_uri = "http://169.254.169.254/latest/meta-data/"
        });

        CreateClient(new MockHandler(configJson, "{}"));

        var result = await _jwksClient!.FetchJwksAsync("https://test.example.com");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.JwksFetchFailed, result.ErrorKind);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public async Task FetchJwksAsync_HttpLocalhost_Allowed()
    {
        var configJson = JsonSerializer.Serialize(new
        {
            issuer = "http://localhost",
            jwks_uri = "http://localhost/.well-known/jwks.json"
        });
        var jwksJson = JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = "RSA", kid = "k1" } }
        });

        CreateClient(new MockHandler(configJson, jwksJson));

        var result = await _jwksClient!.FetchJwksAsync("http://localhost");

        Assert.True(result.IsSuccess);
    }

    private void CreateClient(HttpMessageHandler handler)
    {
        _httpClient = new HttpClient(handler);
        _jwksClient = new JwksClient(_httpClient);
    }

    public void Dispose()
    {
        _jwksClient?.Dispose();
        _httpClient?.Dispose();
    }

    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly string _configJson;
        private readonly string? _jwksJson;
        private readonly HttpStatusCode _configStatus;
        private readonly HttpStatusCode _jwksStatus;

        public MockHandler(string configJson, string? jwksJson,
            HttpStatusCode jwksStatus = HttpStatusCode.OK)
        {
            _configJson = configJson;
            _jwksJson = jwksJson;
            _configStatus = HttpStatusCode.OK;
            _jwksStatus = jwksStatus;
        }

        public MockHandler(HttpStatusCode configStatus)
        {
            _configJson = "";
            _jwksJson = null;
            _configStatus = configStatus;
            _jwksStatus = HttpStatusCode.OK;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.PathAndQuery.Contains("openid-configuration",
                    StringComparison.OrdinalIgnoreCase) == true)
            {
                var response = new HttpResponseMessage(_configStatus);
                response.Content = new StringContent(_configJson, Encoding.UTF8, "application/json");
                return Task.FromResult(response);
            }
            else
            {
                var response = new HttpResponseMessage(_jwksStatus);
                response.Content = new StringContent(
                    _jwksJson ?? "{}", Encoding.UTF8, "application/json");
                return Task.FromResult(response);
            }
        }
    }
}
