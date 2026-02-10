using System.Net;
using System.Text;
using System.Text.Json;
using Sigil.Signing;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class RekorClientTests
{
    private static SignatureEntry CreateEntry() => new()
    {
        KeyId = "sha256:abcdef",
        Algorithm = "ecdsa-p256",
        PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest",
        Value = "BAUG",
        Timestamp = "2026-02-10T12:00:00Z"
    };

    private static SubjectDescriptor CreateSubject() => new()
    {
        Name = "test.txt",
        Digests = new Dictionary<string, string> { ["sha256"] = "abc123def456" }
    };

    [Fact]
    public void Constructor_rejects_http_non_localhost()
    {
        Assert.Throws<ArgumentException>(() =>
            new RekorClient("http://rekor.example.com"));
    }

    [Fact]
    public void Constructor_allows_https()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);

        Assert.Equal("https://rekor.sigstore.dev", client.LogUrl);
    }

    [Fact]
    public void Constructor_allows_localhost()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("http://localhost:3000", httpClient);

        Assert.Equal("http://localhost:3000", client.LogUrl);
    }

    [Fact]
    public async Task AppendAsync_sends_hashedrekord()
    {
        string? capturedBody = null;
        var handler = new FakeHandler(HttpStatusCode.Created, CreateSuccessResponse(), onRequest: async req =>
        {
            if (req.Content is not null)
                capturedBody = await req.Content.ReadAsStringAsync();
        });
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.NotNull(capturedBody);
        Assert.Contains("hashedrekord", capturedBody);
        Assert.Contains("0.0.1", capturedBody);
        Assert.Contains("abc123def456", capturedBody);
    }

    [Fact]
    public async Task AppendAsync_success_returns_receipt()
    {
        var handler = new FakeHandler(HttpStatusCode.Created, CreateSuccessResponse());
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value.LogIndex);
    }

    [Fact]
    public async Task AppendAsync_conflict_returns_existing_entry()
    {
        var handler = new FakeHandler(HttpStatusCode.Conflict, CreateSuccessResponse());
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        // 409 with body = existing entry, should still parse
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task AppendAsync_missing_sha256_fails()
    {
        var handler = new FakeHandler(HttpStatusCode.Created, "{}");
        var httpClient = new HttpClient(handler);

        var subject = new SubjectDescriptor
        {
            Name = "test.txt",
            Digests = new Dictionary<string, string> { ["sha512"] = "abc" }
        };

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.AppendAsync(CreateEntry(), subject);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task AppendAsync_server_error()
    {
        var handler = new FakeHandler(HttpStatusCode.InternalServerError, "internal error");
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.ServerError, result.ErrorKind);
    }

    [Fact]
    public async Task AppendAsync_network_error()
    {
        var handler = new ThrowingHandler(new HttpRequestException("timeout"));
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.AppendAsync(CreateEntry(), CreateSubject());

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.NetworkError, result.ErrorKind);
    }

    [Fact]
    public async Task GetPublicKeyAsync_success()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----");
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.GetPublicKeyAsync();

        Assert.True(result.IsSuccess);
        Assert.Contains("BEGIN PUBLIC KEY", result.Value);
    }

    [Fact]
    public async Task GetCheckpointAsync_success()
    {
        var response = JsonSerializer.Serialize(new
        {
            treeSize = 50000,
            rootHash = "aabbccdd"
        });
        var handler = new FakeHandler(HttpStatusCode.OK, response);
        var httpClient = new HttpClient(handler);

        using var client = new RekorClient("https://rekor.sigstore.dev", httpClient);
        var result = await client.GetCheckpointAsync();

        Assert.True(result.IsSuccess);
        Assert.Equal(50000, result.Value.TreeSize);
    }

    private static string CreateSuccessResponse()
    {
        return JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["uuid123abc"] = new
            {
                logIndex = 42,
                verification = new
                {
                    signedEntryTimestamp = "dGVzdA==",
                    inclusionProof = new
                    {
                        logIndex = 42,
                        treeSize = 100,
                        rootHash = "aabbccdd",
                        hashes = (string[])["1111"]
                    }
                }
            }
        });
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _responseBody;
        private readonly Func<HttpRequestMessage, Task>? _onRequest;

        public FakeHandler(HttpStatusCode statusCode, string responseBody,
            Func<HttpRequestMessage, Task>? onRequest = null)
        {
            _statusCode = statusCode;
            _responseBody = responseBody;
            _onRequest = onRequest;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_onRequest is not null)
                await _onRequest(request);

            return new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, "application/json")
            };
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
