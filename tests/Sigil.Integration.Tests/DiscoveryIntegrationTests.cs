using System.Globalization;
using System.Net;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Discovery;
using Sigil.Keys;
using Sigil.Trust;

namespace Sigil.Integration.Tests;

public class DiscoveryIntegrationTests
{
    [Fact]
    public async Task WellKnownResolver_WithMockHttp_ReturnsBundle()
    {
        // Create a real signed trust bundle
        using var authority = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var authorityFp = KeyFingerprint.Compute(authority.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "Discovery Test Bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = authorityFp.Value, DisplayName = "Authority" }]
        };

        var signResult = BundleSigner.Sign(bundle, authority);
        Assert.True(signResult.IsSuccess);

        var serResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serResult.IsSuccess);
        var bundleJson = serResult.Value;

        // Set up mock HTTP handler
        var handler = new MockHandler(HttpStatusCode.OK, bundleJson);
        using var httpClient = new HttpClient(handler);
        var resolver = new WellKnownResolver(httpClient);

        // Resolve
        var result = await resolver.ResolveAsync("example.com");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://example.com/.well-known/sigil/trust.json", handler.LastRequestUri?.ToString());

        // Verify the returned bundle is valid
        var verifyResult = BundleSigner.Verify(result.Value, authorityFp.Value);
        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value);
    }

    [Fact]
    public void DnsRecordParsing_ValidRecord()
    {
        var records = new List<string>
        {
            "v=spf1 include:example.com ~all",
            "v=sigil1 bundle=https://trust.example.com/bundle.json"
        };

        var result = DnsDiscovery.FindSigilRecord(records);

        Assert.True(result.IsSuccess);
        Assert.Equal("https://trust.example.com/bundle.json", result.Value);
    }

    [Fact]
    public void DnsRecordParsing_NoSigilRecord()
    {
        var records = new List<string> { "v=spf1 include:example.com ~all" };

        var result = DnsDiscovery.FindSigilRecord(records);

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.NotFound, result.ErrorKind);
    }

    [Fact]
    public async Task DiscoveryDispatcher_RoutesToWellKnown_ForHttps()
    {
        var handler = new MockHandler(HttpStatusCode.OK, """{"version":"1.0","kind":"trust-bundle","metadata":{"name":"Test","created":"2024-01-01"}}""");
        using var httpClient = new HttpClient(handler);
        var dispatcher = new DiscoveryDispatcher(httpClient);

        var result = await dispatcher.ResolveAsync("https://example.com/.well-known/sigil/trust.json");

        Assert.True(result.IsSuccess);
        Assert.Contains("trust-bundle", result.Value);
    }

    [Fact]
    public async Task DiscoveryDispatcher_RoutesToWellKnown_ForBareDomain()
    {
        var handler = new MockHandler(HttpStatusCode.OK, """{"kind":"trust-bundle"}""");
        using var httpClient = new HttpClient(handler);
        var dispatcher = new DiscoveryDispatcher(httpClient);

        var result = await dispatcher.ResolveAsync("example.com");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://example.com/.well-known/sigil/trust.json", handler.LastRequestUri?.ToString());
    }

    [Fact]
    public void DispatcherSchemeDetection()
    {
        Assert.Equal("WellKnown", DiscoveryDispatcher.DetectScheme("https://example.com"));
        Assert.Equal("WellKnown", DiscoveryDispatcher.DetectScheme("example.com"));
        Assert.Equal("Dns", DiscoveryDispatcher.DetectScheme("dns:example.com"));
        Assert.Equal("Git", DiscoveryDispatcher.DetectScheme("git:https://github.com/org/repo.git"));
    }

    [Fact]
    public async Task WellKnownResolver_RejectsHttp()
    {
        var handler = new MockHandler(HttpStatusCode.OK, "{}");
        using var httpClient = new HttpClient(handler);
        var resolver = new WellKnownResolver(httpClient);

        var result = await resolver.ResolveAsync("http://evil.com/trust.json");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.InvalidUri, result.ErrorKind);
    }

    [Fact]
    public async Task GitBundleResolver_RejectsUnsafeUrl()
    {
        var resolver = new GitBundleResolver();
        var result = await resolver.ResolveAsync("https://evil.com/repo;rm -rf /");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.InvalidUri, result.ErrorKind);
    }

    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _content;

        public Uri? LastRequestUri { get; private set; }

        public MockHandler(HttpStatusCode statusCode, string content)
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
