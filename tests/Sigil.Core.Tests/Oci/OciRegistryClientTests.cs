using System.Net;
using System.Net.Http.Headers;
using Sigil.Crypto;
using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class OciRegistryClientTests : IDisposable
{
    private readonly MockRegistryHandler _handler = new();
    private readonly HttpClient _httpClient;
    private readonly ImageReference _imageRef;
    private readonly OciRegistryClient _client;

    public OciRegistryClientTests()
    {
        _httpClient = new HttpClient(_handler);
        var parsed = ImageReference.Parse("localhost:5000/test:latest");
        _imageRef = parsed.Value;
        _client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
    }

    public void Dispose()
    {
        _client.Dispose();
        _httpClient.Dispose();
    }

    [Fact]
    public async Task CheckApiAsync_succeeds_on_200()
    {
        _handler.SetResponse(HttpStatusCode.OK, "{}");

        var result = await _client.CheckApiAsync();

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task CheckApiAsync_fails_on_non_200()
    {
        _handler.SetResponse(HttpStatusCode.InternalServerError, "error");

        var result = await _client.CheckApiAsync();

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.RegistryError, result.ErrorKind);
    }

    [Fact]
    public async Task HeadManifestAsync_extracts_descriptor()
    {
        _handler.SetHeadManifestResponse("sha256:abc123", OciMediaTypes.OciManifestV1, 1234);

        var result = await _client.HeadManifestAsync("test", "latest");

        Assert.True(result.IsSuccess);
        Assert.Equal("sha256:abc123", result.Value.Digest);
        Assert.Equal(OciMediaTypes.OciManifestV1, result.Value.MediaType);
        Assert.Equal(1234, result.Value.Size);
    }

    [Fact]
    public async Task HeadManifestAsync_404_returns_ManifestNotFound()
    {
        _handler.SetResponse(HttpStatusCode.NotFound, "");

        var result = await _client.HeadManifestAsync("test", "notfound");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.ManifestNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task GetManifestAsync_returns_bytes_and_manifest()
    {
        var manifestJson = """
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:config123",
                "size": 100
              },
              "layers": [
                {
                  "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": "sha256:layer123",
                  "size": 200
                }
              ]
            }
            """;
        _handler.SetManifestResponse(manifestJson, OciMediaTypes.OciManifestV1);

        var result = await _client.GetManifestAsync("test", "latest");

        Assert.True(result.IsSuccess);
        Assert.NotEmpty(result.Value.Bytes);
        Assert.Equal(2, result.Value.Manifest.SchemaVersion);
        Assert.Equal(OciMediaTypes.OciManifestV1, result.Value.Descriptor.MediaType);
    }

    [Fact]
    public async Task GetBlobAsync_returns_blob_bytes()
    {
        var blobData = System.Text.Encoding.UTF8.GetBytes("blob content");
        _handler.SetBlobResponse(blobData);

        var result = await _client.GetBlobAsync("test", "sha256:blobdigest");

        Assert.True(result.IsSuccess);
        Assert.Equal(blobData, result.Value);
    }

    [Fact]
    public async Task UploadBlobAsync_post_put_succeeds()
    {
        var data = System.Text.Encoding.UTF8.GetBytes("test blob data");
        _handler.SetUploadResponse("/v2/test/blobs/uploads/session123");

        var result = await _client.UploadBlobAsync("test", data);

        Assert.True(result.IsSuccess);
        var expectedDigest = $"sha256:{HashAlgorithms.Sha256Hex(data)}";
        Assert.Equal(expectedDigest, result.Value.Digest);
        Assert.Equal(data.Length, result.Value.Size);
    }

    [Fact]
    public async Task UploadBlobAsync_failure_returns_BlobUploadFailed()
    {
        _handler.SetResponse(HttpStatusCode.InternalServerError, "error");

        var result = await _client.UploadBlobAsync("test", [1, 2, 3]);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.BlobUploadFailed, result.ErrorKind);
    }

    [Fact]
    public async Task PushManifestAsync_puts_with_correct_content_type()
    {
        _handler.SetPushManifestResponse("sha256:pushed123");
        var manifestBytes = System.Text.Encoding.UTF8.GetBytes("{}");

        var result = await _client.PushManifestAsync(
            "test", "sha256:ref", manifestBytes, OciMediaTypes.OciManifestV1);

        Assert.True(result.IsSuccess);
        Assert.Equal("sha256:pushed123", result.Value);
        Assert.Equal(OciMediaTypes.OciManifestV1, _handler.LastPutContentType);
    }

    [Fact]
    public async Task GetReferrersAsync_returns_filtered_list()
    {
        var referrersJson = $$"""
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.index.v1+json",
              "manifests": [
                {
                  "mediaType": "application/vnd.oci.image.manifest.v1+json",
                  "digest": "sha256:sig1",
                  "size": 500,
                  "artifactType": "application/vnd.sigil.signature.v1+json"
                }
              ]
            }
            """;
        _handler.SetReferrersResponse(referrersJson);

        var result = await _client.GetReferrersAsync("test", "sha256:abc",
            OciMediaTypes.SigilSignature);

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
        Assert.Equal("sha256:sig1", result.Value[0].Digest);
        Assert.Equal(OciMediaTypes.SigilSignature, result.Value[0].ArtifactType);
    }

    [Fact]
    public async Task GetReferrersAsync_404_returns_ReferrersNotSupported()
    {
        _handler.SetResponse(HttpStatusCode.NotFound, "");

        var result = await _client.GetReferrersAsync("test", "sha256:abc");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.ReferrersNotSupported, result.ErrorKind);
    }

    [Fact]
    public async Task GetReferrersAsync_empty_manifests()
    {
        var json = """
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.index.v1+json",
              "manifests": []
            }
            """;
        _handler.SetReferrersResponse(json);

        var result = await _client.GetReferrersAsync("test", "sha256:abc");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public async Task Timeout_returns_OciResult_Fail()
    {
        _handler.SimulateTimeout = true;

        var result = await _client.CheckApiAsync(new CancellationToken(true));

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.Timeout, result.ErrorKind);
    }

    private sealed class MockRegistryHandler : HttpMessageHandler
    {
        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string _content = "";
        private string? _headDigest;
        private string? _headMediaType;
        private long _headSize;
        private byte[]? _blobData;
        private string? _uploadLocation;
        private string? _pushDigest;
        private string? _referrersJson;
        private string? _manifestJson;
        private string? _manifestMediaType;

        public bool SimulateTimeout { get; set; }
        public string? LastPutContentType { get; private set; }

        public void SetResponse(HttpStatusCode status, string content)
        {
            _statusCode = status;
            _content = content;
        }

        public void SetHeadManifestResponse(string digest, string mediaType, long size)
        {
            _headDigest = digest;
            _headMediaType = mediaType;
            _headSize = size;
        }

        public void SetManifestResponse(string json, string mediaType)
        {
            _manifestJson = json;
            _manifestMediaType = mediaType;
        }

        public void SetBlobResponse(byte[] data) => _blobData = data;

        public void SetUploadResponse(string location) => _uploadLocation = location;

        public void SetPushManifestResponse(string digest) => _pushDigest = digest;

        public void SetReferrersResponse(string json) => _referrersJson = json;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            if (SimulateTimeout)
                throw new OperationCanceledException();

            var path = request.RequestUri?.PathAndQuery ?? "";

            // HEAD manifest
            if (request.Method == HttpMethod.Head && path.Contains("/manifests/"))
            {
                if (_headDigest is not null)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.OK);
                    response.Headers.Add("Docker-Content-Digest", _headDigest);
                    response.Content = new StringContent("");
                    response.Content.Headers.ContentType = new MediaTypeHeaderValue(_headMediaType!);
                    response.Content.Headers.ContentLength = _headSize;
                    return Task.FromResult(response);
                }
            }

            // GET manifest
            if (request.Method == HttpMethod.Get && path.Contains("/manifests/") && !path.Contains("/referrers/"))
            {
                if (_manifestJson is not null)
                {
                    var bytes = System.Text.Encoding.UTF8.GetBytes(_manifestJson);
                    var digest = $"sha256:{HashAlgorithms.Sha256Hex(bytes)}";
                    var response = new HttpResponseMessage(HttpStatusCode.OK);
                    response.Content = new ByteArrayContent(bytes);
                    response.Content.Headers.ContentType = new MediaTypeHeaderValue(_manifestMediaType!);
                    response.Headers.Add("Docker-Content-Digest", digest);
                    return Task.FromResult(response);
                }
            }

            // GET blob
            if (request.Method == HttpMethod.Get && path.Contains("/blobs/") && !path.Contains("/uploads/"))
            {
                if (_blobData is not null)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.OK);
                    response.Content = new ByteArrayContent(_blobData);
                    return Task.FromResult(response);
                }
            }

            // POST blob upload
            if (request.Method == HttpMethod.Post && path.Contains("/blobs/uploads/"))
            {
                if (_uploadLocation is not null)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.Accepted);
                    response.Headers.Location = new Uri(_uploadLocation, UriKind.Relative);
                    return Task.FromResult(response);
                }
            }

            // PUT blob upload
            if (request.Method == HttpMethod.Put && path.Contains("/blobs/uploads/"))
            {
                var response = new HttpResponseMessage(HttpStatusCode.Created);
                return Task.FromResult(response);
            }

            // PUT manifest
            if (request.Method == HttpMethod.Put && path.Contains("/manifests/"))
            {
                LastPutContentType = request.Content?.Headers.ContentType?.MediaType;
                if (_pushDigest is not null)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.Created);
                    response.Headers.Add("Docker-Content-Digest", _pushDigest);
                    return Task.FromResult(response);
                }
            }

            // GET referrers
            if (request.Method == HttpMethod.Get && path.Contains("/referrers/"))
            {
                if (_referrersJson is not null)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.OK);
                    response.Content = new StringContent(_referrersJson);
                    return Task.FromResult(response);
                }
            }

            // Default
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_content)
            });
        }
    }
}
