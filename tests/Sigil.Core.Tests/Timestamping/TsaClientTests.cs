using System.Net;
using Sigil.Timestamping;

namespace Sigil.Core.Tests.Timestamping;

public class TsaClientTests : IDisposable
{
    private readonly MockTsaHttpHandler _handler;
    private readonly HttpClient _httpClient;
    private readonly TsaClient _client;

    public TsaClientTests()
    {
        _handler = new MockTsaHttpHandler();
        _httpClient = new HttpClient(_handler);
        _client = new TsaClient(_httpClient);
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [Fact]
    public async Task Timeout_returns_Timeout()
    {
        _handler.SimulateDelay = true;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(10));

        var result = await _client.RequestTimestampAsync(
            new Uri("http://localhost/tsa"), [1, 2, 3], cts.Token);

        Assert.False(result.IsSuccess);
        Assert.Equal(TimestampErrorKind.Timeout, result.ErrorKind);
    }

    [Fact]
    public async Task HttpError_returns_NetworkError()
    {
        _handler.StatusCode = HttpStatusCode.InternalServerError;

        var result = await _client.RequestTimestampAsync(
            new Uri("http://localhost/tsa"), [1, 2, 3]);

        Assert.False(result.IsSuccess);
        Assert.Equal(TimestampErrorKind.NetworkError, result.ErrorKind);
        Assert.Contains("500", result.ErrorMessage);
    }

    [Fact]
    public async Task MalformedResponse_returns_InvalidResponse()
    {
        _handler.StatusCode = HttpStatusCode.OK;
        _handler.ResponseBytes = [0x00, 0x01, 0x02]; // garbage

        var result = await _client.RequestTimestampAsync(
            new Uri("http://localhost/tsa"), [1, 2, 3]);

        Assert.False(result.IsSuccess);
        Assert.Equal(TimestampErrorKind.InvalidResponse, result.ErrorKind);
    }

    [Fact]
    public async Task ContentType_is_timestamp_query()
    {
        _handler.StatusCode = HttpStatusCode.OK;
        _handler.ResponseBytes = [0x00]; // will fail parsing but we can check content type

        _ = await _client.RequestTimestampAsync(
            new Uri("http://localhost/tsa"), [1, 2, 3]);

        Assert.NotNull(_handler.LastRequestContentType);
        Assert.Equal("application/timestamp-query", _handler.LastRequestContentType);
    }

    [Fact]
    public async Task HttpException_returns_NetworkError()
    {
        _handler.ThrowHttpException = true;

        var result = await _client.RequestTimestampAsync(
            new Uri("http://localhost/tsa"), [1, 2, 3]);

        Assert.False(result.IsSuccess);
        Assert.Equal(TimestampErrorKind.NetworkError, result.ErrorKind);
    }

    private sealed class MockTsaHttpHandler : HttpMessageHandler
    {
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
        public byte[]? ResponseBytes { get; set; }
        public bool SimulateDelay { get; set; }
        public bool ThrowHttpException { get; set; }
        public string? LastRequestContentType { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequestContentType = request.Content?.Headers.ContentType?.MediaType;

            if (ThrowHttpException)
                throw new HttpRequestException("Connection refused");

            if (SimulateDelay)
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);

            var response = new HttpResponseMessage(StatusCode);
            if (ResponseBytes is not null)
                response.Content = new ByteArrayContent(ResponseBytes);
            else
                response.Content = new ByteArrayContent([]);

            return response;
        }
    }
}
