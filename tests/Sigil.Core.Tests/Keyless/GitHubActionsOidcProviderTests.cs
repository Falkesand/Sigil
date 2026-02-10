using System.Net;
using System.Text;
using System.Text.Json;
using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class GitHubActionsOidcProviderTests : IDisposable
{
    private HttpClient? _httpClient;
    private GitHubActionsOidcProvider? _provider;

    [Fact]
    public async Task AcquireTokenAsync_Success_ReturnsToken()
    {
        var responseJson = JsonSerializer.Serialize(new { value = "my-jwt-token" });
        CreateProvider("https://actions.example.com/token?", "bearer-token", responseJson);

        var result = await _provider!.AcquireTokenAsync("sigil:sha256:abc");

        Assert.True(result.IsSuccess);
        Assert.Equal("my-jwt-token", result.Value);
    }

    [Fact]
    public async Task AcquireTokenAsync_NetworkError_Fails()
    {
        var handler = new FailingHandler();
        _httpClient = new HttpClient(handler);
        _provider = new GitHubActionsOidcProvider("https://actions.example.com/token?", "token", _httpClient);

        var result = await _provider.AcquireTokenAsync("sigil:sha256:abc");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.NetworkError, result.ErrorKind);
    }

    [Fact]
    public async Task AcquireTokenAsync_Non200_Fails()
    {
        CreateProvider("https://actions.example.com/token?", "token", "", HttpStatusCode.Forbidden);

        var result = await _provider!.AcquireTokenAsync("sigil:sha256:abc");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenAcquisitionFailed, result.ErrorKind);
    }

    [Fact]
    public async Task AcquireTokenAsync_MissingValueField_Fails()
    {
        var responseJson = JsonSerializer.Serialize(new { other = "data" });
        CreateProvider("https://actions.example.com/token?", "token", responseJson);

        var result = await _provider!.AcquireTokenAsync("sigil:sha256:abc");

        Assert.False(result.IsSuccess);
        Assert.Contains("value", result.ErrorMessage);
    }

    [Fact]
    public void IsAvailable_NoEnvVars_ReturnsFalse()
    {
        // In test environment, these env vars are not set
        Assert.False(GitHubActionsOidcProvider.IsAvailable());
    }

    private void CreateProvider(string requestUrl, string requestToken, string responseBody,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var handler = new MockHandler(responseBody, statusCode);
        _httpClient = new HttpClient(handler);
        _provider = new GitHubActionsOidcProvider(requestUrl, requestToken, _httpClient);
    }

    public void Dispose()
    {
        _provider?.Dispose();
        _httpClient?.Dispose();
    }

    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly string _responseBody;
        private readonly HttpStatusCode _statusCode;

        public MockHandler(string responseBody, HttpStatusCode statusCode)
        {
            _responseBody = responseBody;
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }

    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Connection refused");
        }
    }
}
