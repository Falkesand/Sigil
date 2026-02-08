using System.Net;
using Sigil.Discovery;

namespace Sigil.Core.Tests.Discovery;

public class WellKnownResolverTests : IDisposable
{
    private readonly MockHttpMessageHandler _handler;
    private readonly HttpClient _httpClient;
    private readonly WellKnownResolver _resolver;

    public WellKnownResolverTests()
    {
        _handler = new MockHttpMessageHandler();
        _httpClient = new HttpClient(_handler);
        _resolver = new WellKnownResolver(_httpClient);
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [Fact]
    public async Task ResolveAsync_constructs_well_known_url_and_returns_json()
    {
        var bundleJson = """{"version":"1.0","kind":"trust-bundle"}""";
        _handler.SetResponse(HttpStatusCode.OK, bundleJson);

        var result = await _resolver.ResolveAsync("example.com");

        Assert.True(result.IsSuccess);
        Assert.Equal(bundleJson, result.Value);
        Assert.Equal("https://example.com/.well-known/sigil/trust.json", _handler.LastRequestUri?.ToString());
    }

    [Fact]
    public async Task ResolveAsync_with_https_url_uses_it_directly()
    {
        var bundleJson = """{"version":"1.0"}""";
        _handler.SetResponse(HttpStatusCode.OK, bundleJson);

        var result = await _resolver.ResolveAsync("https://corp.example.com/.well-known/sigil/trust.json");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://corp.example.com/.well-known/sigil/trust.json", _handler.LastRequestUri?.ToString());
    }

    [Fact]
    public async Task ResolveAsync_404_returns_NotFound()
    {
        _handler.SetResponse(HttpStatusCode.NotFound, "");

        var result = await _resolver.ResolveAsync("missing.example.com");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.NotFound, result.ErrorKind);
    }

    [Fact]
    public async Task ResolveAsync_500_returns_NetworkError()
    {
        _handler.SetResponse(HttpStatusCode.InternalServerError, "");

        var result = await _resolver.ResolveAsync("broken.example.com");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.NetworkError, result.ErrorKind);
    }

    [Fact]
    public async Task ResolveAsync_rejects_http_non_localhost()
    {
        var result = await _resolver.ResolveAsync("http://evil.com/trust.json");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.InvalidUri, result.ErrorKind);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public async Task ResolveAsync_allows_http_localhost()
    {
        var bundleJson = """{"local":true}""";
        _handler.SetResponse(HttpStatusCode.OK, bundleJson);

        var result = await _resolver.ResolveAsync("http://localhost:8080/trust.json");

        Assert.True(result.IsSuccess);
        Assert.Equal(bundleJson, result.Value);
    }

    [Fact]
    public async Task ResolveAsync_cancellation_returns_Timeout()
    {
        _handler.SetResponse(HttpStatusCode.OK, "data", simulateDelay: true);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(10));

        var result = await _resolver.ResolveAsync("slow.example.com", cts.Token);

        Assert.False(result.IsSuccess);
        Assert.True(result.ErrorKind is DiscoveryErrorKind.Timeout or DiscoveryErrorKind.NetworkError);
    }

    private sealed class MockHttpMessageHandler : HttpMessageHandler
    {
        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string _content = "";
        private bool _simulateDelay;

        public Uri? LastRequestUri { get; private set; }

        public void SetResponse(HttpStatusCode statusCode, string content, bool simulateDelay = false)
        {
            _statusCode = statusCode;
            _content = content;
            _simulateDelay = simulateDelay;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;

            if (_simulateDelay)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            }

            return new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_content)
            };
        }
    }
}
