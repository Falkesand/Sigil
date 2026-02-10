using System.Net;
using System.Text;
using System.Text.Json;
using Sigil.Signing;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class SigilLogClientTests
{
    private static SignatureEntry CreateEntry() => new()
    {
        KeyId = "sha256:abcdef",
        Algorithm = "ecdsa-p256",
        PublicKey = "AQID",
        Value = "BAUG",
        Timestamp = "2026-02-10T12:00:00Z"
    };

    private static SubjectDescriptor CreateSubject() => new()
    {
        Name = "test.txt",
        Digests = new Dictionary<string, string> { ["sha256"] = "abc123" }
    };

    [Fact]
    public void Constructor_rejects_http_non_localhost()
    {
        Assert.Throws<ArgumentException>(() =>
            new SigilLogClient("http://log.example.com", "key123"));
    }

    [Fact]
    public void Constructor_allows_http_localhost()
    {
        using var client = new SigilLogClient("http://localhost:5000", "key123");

        Assert.Equal("http://localhost:5000", client.LogUrl);
    }

    [Fact]
    public void Constructor_allows_https()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);

        Assert.Equal("https://log.example.com", client.LogUrl);
    }

    [Fact]
    public void Constructor_trims_trailing_slash()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com/", "key123", httpClient);

        Assert.Equal("https://log.example.com", client.LogUrl);
    }

    [Fact]
    public void Constructor_rejects_empty_url()
    {
        Assert.Throws<ArgumentException>(() =>
            new SigilLogClient("", "key123"));
    }

    [Fact]
    public void Constructor_rejects_empty_api_key()
    {
        Assert.Throws<ArgumentException>(() =>
            new SigilLogClient("https://log.example.com", ""));
    }

    [Fact]
    public async Task AppendAsync_sends_api_key_header()
    {
        string? capturedApiKey = null;
        var handler = new FakeHandler(HttpStatusCode.Created, CreateSuccessResponse(), onRequest: req =>
        {
            if (req.Headers.TryGetValues("X-Api-Key", out var values))
                capturedApiKey = values.First();
        });
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "secret-key", httpClient);
        await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.Equal("secret-key", capturedApiKey);
    }

    [Fact]
    public async Task AppendAsync_success_returns_receipt()
    {
        var handler = new FakeHandler(HttpStatusCode.Created, CreateSuccessResponse());
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.True(result.IsSuccess);
        Assert.Equal("https://log.example.com", result.Value.LogUrl);
        Assert.Equal(42, result.Value.LogIndex);
    }

    [Fact]
    public async Task AppendAsync_unauthorized_returns_auth_error()
    {
        var handler = new FakeHandler(HttpStatusCode.Unauthorized, "");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "bad-key", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.AuthenticationFailed, result.ErrorKind);
    }

    [Fact]
    public async Task AppendAsync_conflict_returns_duplicate()
    {
        var handler = new FakeHandler(HttpStatusCode.Conflict, "");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.DuplicateEntry, result.ErrorKind);
    }

    [Fact]
    public async Task AppendAsync_server_error_returns_error()
    {
        var handler = new FakeHandler(HttpStatusCode.InternalServerError, "");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.ServerError, result.ErrorKind);
    }

    [Fact]
    public async Task AppendAsync_network_error_returns_error()
    {
        var handler = new ThrowingHandler(new HttpRequestException("connection refused"));
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.NetworkError, result.ErrorKind);
    }

    [Fact]
    public async Task GetCheckpointAsync_success()
    {
        var checkpoint = new SignedCheckpoint
        {
            TreeSize = 100,
            RootHash = "aabbccdd",
            Timestamp = "2026-02-10T12:00:00Z",
            Signature = "dGVzdA=="
        };
        var json = JsonSerializer.Serialize(checkpoint);
        var handler = new FakeHandler(HttpStatusCode.OK, json);
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.GetCheckpointAsync();

        Assert.True(result.IsSuccess);
        Assert.Equal(100, result.Value.TreeSize);
    }

    [Fact]
    public async Task GetInclusionProofAsync_success()
    {
        var proof = new RemoteInclusionProof
        {
            LeafIndex = 5,
            TreeSize = 16,
            RootHash = "aabb",
            Hashes = ["1111", "2222"]
        };
        var json = JsonSerializer.Serialize(proof);
        var handler = new FakeHandler(HttpStatusCode.OK, json);
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.GetInclusionProofAsync(5);

        Assert.True(result.IsSuccess);
        Assert.Equal(5, result.Value.LeafIndex);
        Assert.Equal(2, result.Value.Hashes.Count);
    }

    [Fact]
    public async Task GetPublicKeyAsync_success()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "MFkwEwYH...");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.GetPublicKeyAsync();

        Assert.True(result.IsSuccess);
        Assert.Equal("MFkwEwYH...", result.Value);
    }

    [Fact]
    public async Task GetPublicKeyAsync_server_error()
    {
        var handler = new FakeHandler(HttpStatusCode.InternalServerError, "");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.GetPublicKeyAsync();

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.ServerError, result.ErrorKind);
    }

    [Fact]
    public async Task GetCheckpointAsync_invalid_json()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "not json");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.GetCheckpointAsync();

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidResponse, result.ErrorKind);
    }

    [Fact]
    public async Task AppendAsync_invalid_response_json()
    {
        var handler = new FakeHandler(HttpStatusCode.Created, "not json");
        var httpClient = new HttpClient(handler);

        using var client = new SigilLogClient("https://log.example.com", "key123", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidResponse, result.ErrorKind);
    }

    private static string CreateSuccessResponse()
    {
        return JsonSerializer.Serialize(new
        {
            logIndex = 42,
            signedCheckpoint = "dGVzdA==",
            inclusionProof = new
            {
                leafIndex = 42,
                treeSize = 100,
                rootHash = "aabbccdd",
                hashes = (string[])["1111", "2222"]
            }
        });
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _responseBody;
        private readonly Action<HttpRequestMessage>? _onRequest;

        public FakeHandler(HttpStatusCode statusCode, string responseBody,
            Action<HttpRequestMessage>? onRequest = null)
        {
            _statusCode = statusCode;
            _responseBody = responseBody;
            _onRequest = onRequest;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onRequest?.Invoke(request);
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        private readonly Exception _exception;

        public ThrowingHandler(Exception exception)
        {
            _exception = exception;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw _exception;
        }
    }
}
