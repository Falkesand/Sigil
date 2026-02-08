using System.Net;
using Sigil.Discovery;

namespace Sigil.Core.Tests.Discovery;

public class DiscoveryDispatcherTests
{
    [Theory]
    [InlineData("https://example.com", "WellKnown")]
    [InlineData("https://example.com/.well-known/sigil/trust.json", "WellKnown")]
    [InlineData("http://localhost:8080/trust.json", "WellKnown")]
    [InlineData("example.com", "WellKnown")]
    public void DetectScheme_routes_to_WellKnown(string input, string expected)
    {
        var scheme = DiscoveryDispatcher.DetectScheme(input);
        Assert.Equal(expected, scheme);
    }

    [Theory]
    [InlineData("dns:example.com", "Dns")]
    [InlineData("dns:corp.example.com", "Dns")]
    public void DetectScheme_routes_to_Dns(string input, string expected)
    {
        var scheme = DiscoveryDispatcher.DetectScheme(input);
        Assert.Equal(expected, scheme);
    }

    [Theory]
    [InlineData("git:https://github.com/org/repo.git", "Git")]
    [InlineData("git:https://github.com/org/repo.git#v2", "Git")]
    public void DetectScheme_routes_to_Git(string input, string expected)
    {
        var scheme = DiscoveryDispatcher.DetectScheme(input);
        Assert.Equal(expected, scheme);
    }

    [Fact]
    public async Task ResolveAsync_dispatches_to_WellKnown_for_https()
    {
        var handler = new MockHttpMessageHandler(HttpStatusCode.OK, """{"kind":"trust-bundle"}""");
        var httpClient = new HttpClient(handler);
        var dispatcher = new DiscoveryDispatcher(httpClient);

        var result = await dispatcher.ResolveAsync("https://example.com/.well-known/sigil/trust.json");

        Assert.True(result.IsSuccess);
        Assert.Contains("trust-bundle", result.Value);
    }

    [Fact]
    public async Task ResolveAsync_dispatches_to_WellKnown_for_bare_domain()
    {
        var handler = new MockHttpMessageHandler(HttpStatusCode.OK, """{"kind":"trust-bundle"}""");
        var httpClient = new HttpClient(handler);
        var dispatcher = new DiscoveryDispatcher(httpClient);

        var result = await dispatcher.ResolveAsync("example.com");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://example.com/.well-known/sigil/trust.json", handler.LastRequestUri?.ToString());
    }

    [Fact]
    public async Task ResolveAsync_returns_error_for_empty_input()
    {
        var dispatcher = new DiscoveryDispatcher(new HttpClient());

        await Assert.ThrowsAsync<ArgumentException>(() => dispatcher.ResolveAsync(""));
    }

    private sealed class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _content;

        public Uri? LastRequestUri { get; private set; }

        public MockHttpMessageHandler(HttpStatusCode statusCode, string content)
        {
            _statusCode = statusCode;
            _content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_content)
            });
        }
    }
}
