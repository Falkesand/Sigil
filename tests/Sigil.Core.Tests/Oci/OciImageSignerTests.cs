using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Oci;
using Sigil.Signing;

namespace Sigil.Core.Tests.Oci;

public class OciImageSignerTests : IDisposable
{
    private readonly MockSignFlowHandler _handler = new();
    private readonly HttpClient _httpClient;
    private readonly ISigner _signer;
    private readonly ImageReference _imageRef;

    public OciImageSignerTests()
    {
        _httpClient = new HttpClient(_handler);
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _imageRef = ImageReference.Parse("localhost:5000/test:latest").Value;
    }

    public void Dispose()
    {
        _signer.Dispose();
        _httpClient.Dispose();
    }

    [Fact]
    public async Task Full_sign_flow_succeeds()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        var result = await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.True(result.IsSuccess);
        Assert.StartsWith("sha256:", result.Value.ManifestDigest);
        Assert.NotEmpty(result.Value.KeyId);
        Assert.Equal("ecdsa-p256", result.Value.Algorithm);
    }

    [Fact]
    public async Task Subject_name_is_full_image_reference()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        var result = await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.True(result.IsSuccess);
        // Verify the envelope was uploaded (check handler captured it)
        Assert.NotNull(_handler.UploadedEnvelopeJson);
        var envelope = JsonSerializer.Deserialize<SignatureEnvelope>(_handler.UploadedEnvelopeJson);
        Assert.NotNull(envelope);
        Assert.Equal("localhost:5000/test:latest", envelope.Subject.Name);
    }

    [Fact]
    public async Task Subject_digests_match_manifest_bytes()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.NotNull(_handler.UploadedEnvelopeJson);
        var envelope = JsonSerializer.Deserialize<SignatureEnvelope>(_handler.UploadedEnvelopeJson);
        Assert.NotNull(envelope);

        var (sha256, sha512) = HashAlgorithms.ComputeDigests(
            Encoding.UTF8.GetBytes(MockSignFlowHandler.ManifestJson));
        Assert.Equal(sha256, envelope.Subject.Digests["sha256"]);
        Assert.Equal(sha512, envelope.Subject.Digests["sha512"]);
    }

    [Fact]
    public async Task Subject_mediaType_from_manifest()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.NotNull(_handler.UploadedEnvelopeJson);
        var envelope = JsonSerializer.Deserialize<SignatureEnvelope>(_handler.UploadedEnvelopeJson);
        Assert.NotNull(envelope);
        Assert.Equal(OciMediaTypes.OciManifestV1, envelope.Subject.MediaType);
    }

    [Fact]
    public async Task HEAD_failure_returns_error()
    {
        _handler.HeadManifestFails = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.ManifestNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task Blob_upload_failure_returns_error()
    {
        _handler.BlobUploadFails = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.BlobUploadFailed, result.ErrorKind);
    }

    [Fact]
    public async Task Manifest_push_failure_returns_error()
    {
        _handler.PushManifestFails = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.RegistryError, result.ErrorKind);
    }

    [Fact]
    public async Task Label_passed_through()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        await OciImageSigner.SignAsync(client, _imageRef, _signer, label: "release");

        Assert.NotNull(_handler.UploadedEnvelopeJson);
        var envelope = JsonSerializer.Deserialize<SignatureEnvelope>(_handler.UploadedEnvelopeJson);
        Assert.NotNull(envelope);
        Assert.Equal("release", envelope.Signatures[0].Label);
    }

    [Fact]
    public async Task Vault_signer_async_path()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        // EcdsaSigner implements ISigner with default SignAsync → Sign(), simulating vault path
        var result = await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task Signature_is_verifiable()
    {
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);
        await OciImageSigner.SignAsync(client, _imageRef, _signer);

        Assert.NotNull(_handler.UploadedEnvelopeJson);
        var envelope = JsonSerializer.Deserialize<SignatureEnvelope>(_handler.UploadedEnvelopeJson)!;

        var manifestBytes = Encoding.UTF8.GetBytes(MockSignFlowHandler.ManifestJson);
        var verifyResult = SignatureValidator.Verify(manifestBytes, envelope);
        Assert.True(verifyResult.AllSignaturesValid);
    }

    /// <summary>
    /// Mock HTTP handler simulating a full OCI sign flow.
    /// </summary>
    private sealed class MockSignFlowHandler : HttpMessageHandler
    {
        public const string ManifestJson = """
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

        private static readonly byte[] ManifestBytes = Encoding.UTF8.GetBytes(ManifestJson);
        private static readonly string ManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(ManifestBytes)}";

        public bool HeadManifestFails { get; set; }
        public bool BlobUploadFails { get; set; }
        public bool PushManifestFails { get; set; }
        public string? UploadedEnvelopeJson { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri?.PathAndQuery ?? "";

            // HEAD manifest
            if (request.Method == HttpMethod.Head && path.Contains("/manifests/"))
            {
                if (HeadManifestFails)
                    return new HttpResponseMessage(HttpStatusCode.NotFound);

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.Add("Docker-Content-Digest", ManifestDigest);
                response.Content = new StringContent("");
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(OciMediaTypes.OciManifestV1);
                response.Content.Headers.ContentLength = ManifestBytes.Length;
                return response;
            }

            // GET manifest
            if (request.Method == HttpMethod.Get && path.Contains("/manifests/") && !path.Contains("/referrers/"))
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ByteArrayContent(ManifestBytes);
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(OciMediaTypes.OciManifestV1);
                response.Headers.Add("Docker-Content-Digest", ManifestDigest);
                return response;
            }

            // POST blob upload
            if (request.Method == HttpMethod.Post && path.Contains("/blobs/uploads/"))
            {
                if (BlobUploadFails)
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);

                var response = new HttpResponseMessage(HttpStatusCode.Accepted);
                response.Headers.Location = new Uri("/v2/test/blobs/uploads/session1", UriKind.Relative);
                return response;
            }

            // PUT blob upload
            if (request.Method == HttpMethod.Put && path.Contains("/blobs/uploads/"))
            {
                // Capture the envelope blob (the larger one, not the empty config)
                if (request.Content is not null)
                {
                    var data = await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                    if (data.Length > 10) // Skip the "{}" empty config
                    {
                        UploadedEnvelopeJson = Encoding.UTF8.GetString(data);
                    }
                }
                return new HttpResponseMessage(HttpStatusCode.Created);
            }

            // PUT manifest (push signature)
            if (request.Method == HttpMethod.Put && path.Contains("/manifests/"))
            {
                if (PushManifestFails)
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);

                var content = request.Content is not null
                    ? await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false) : [];
                var digest = $"sha256:{HashAlgorithms.Sha256Hex(content)}";
                var response = new HttpResponseMessage(HttpStatusCode.Created);
                response.Headers.Add("Docker-Content-Digest", digest);
                return response;
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
