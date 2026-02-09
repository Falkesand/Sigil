using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Oci;
using Sigil.Signing;

namespace Sigil.Core.Tests.Oci;

public class OciImageVerifierTests : IDisposable
{
    private readonly MockVerifyFlowHandler _handler;
    private readonly HttpClient _httpClient;
    private readonly ImageReference _imageRef;

    public OciImageVerifierTests()
    {
        // Create a real signature for the manifest
        _handler = new MockVerifyFlowHandler();
        _httpClient = new HttpClient(_handler);
        _imageRef = ImageReference.Parse("localhost:5000/test:latest").Value;
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [Fact]
    public async Task Full_verify_flow_succeeds()
    {
        _handler.AddValidSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value.SignatureCount);
        Assert.True(result.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task No_referrers_returns_SignatureNotFound()
    {
        // No signatures added
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.SignatureNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task Multiple_signatures_verified()
    {
        _handler.AddValidSignature();
        _handler.AddValidSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.SignatureCount);
        Assert.True(result.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task Invalid_signature_detected()
    {
        _handler.AddInvalidSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value.SignatureCount);
        Assert.False(result.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task Tampered_manifest_detected()
    {
        _handler.AddValidSignature();
        _handler.TamperManifest = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task AllSignaturesValid_and_AnySignatureValid()
    {
        _handler.AddValidSignature();
        _handler.AddInvalidSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.AllSignaturesValid);
        Assert.True(result.Value.AnySignatureValid);
    }

    [Fact]
    public async Task ManifestDigest_in_result_correct()
    {
        _handler.AddValidSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.Equal(MockVerifyFlowHandler.ManifestDigest, result.Value.ManifestDigest);
    }

    [Fact]
    public async Task HEAD_failure_returns_error()
    {
        _handler.HeadFails = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.ManifestNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task Malformed_signature_blob_skipped()
    {
        _handler.AddMalformedSignature();
        _handler.AddValidSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        // Malformed one is skipped, valid one succeeds
        Assert.Equal(1, result.Value.SignatureCount);
        Assert.True(result.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task Referrers_not_supported_returns_error()
    {
        _handler.ReferrersNotSupported = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.ReferrersNotSupported, result.ErrorKind);
    }

    [Fact]
    public async Task Empty_layers_in_sig_manifest_skipped()
    {
        _handler.AddEmptyLayerSignature();
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.Equal(0, result.Value.SignatureCount);
    }

    [Fact]
    public async Task Missing_blob_skipped()
    {
        _handler.AddValidSignature();
        _handler.BlobNotFound = true;
        using var client = new OciRegistryClient(_imageRef, httpClient: _httpClient);

        var result = await OciImageVerifier.VerifyAsync(client, _imageRef);

        Assert.True(result.IsSuccess);
        Assert.Equal(0, result.Value.SignatureCount);
    }

    /// <summary>
    /// Simulates a full OCI verify flow with real signatures.
    /// </summary>
    private sealed class MockVerifyFlowHandler : HttpMessageHandler
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
        public static readonly string ManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(ManifestBytes)}";

        // Each entry: (sigManifestDigest, sigManifestJson, blobDigest, blobBytes)
        private readonly List<(string Digest, string ManifestJson, string BlobDigest, byte[] BlobBytes)> _signatures = [];

        public bool HeadFails { get; set; }
        public bool ReferrersNotSupported { get; set; }
        public bool TamperManifest { get; set; }
        public bool BlobNotFound { get; set; }

        public void AddValidSignature()
        {
            using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
            var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
            var (sha256, sha512) = HashAlgorithms.ComputeDigests(ManifestBytes);

            var subject = new SubjectDescriptor
            {
                Name = "localhost:5000/test:latest",
                Digests = new Dictionary<string, string> { ["sha256"] = sha256, ["sha512"] = sha512 },
                MediaType = OciMediaTypes.OciManifestV1
            };

            var envelope = new SignatureEnvelope { Subject = subject };
            ArtifactSigner.AppendSignature(envelope, ManifestBytes, signer, fingerprint);

            AddEnvelopeAsSignature(envelope);
        }

        public void AddInvalidSignature()
        {
            // Create envelope with wrong digests
            var subject = new SubjectDescriptor
            {
                Name = "localhost:5000/test:latest",
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = HashAlgorithms.Sha256Hex(ManifestBytes),
                    ["sha512"] = HashAlgorithms.Sha512Hex(ManifestBytes)
                },
                MediaType = OciMediaTypes.OciManifestV1
            };

            using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
            var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
            var envelope = new SignatureEnvelope { Subject = subject };

            // Sign different data to make signature invalid
            var fakePayload = Encoding.UTF8.GetBytes("wrong data");
            var sig = signer.Sign(fakePayload);

            envelope.Signatures.Add(new SignatureEntry
            {
                KeyId = fingerprint.Value,
                Algorithm = "ecdsa-p256",
                PublicKey = Convert.ToBase64String(signer.PublicKey),
                Value = Convert.ToBase64String(sig),
                Timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    System.Globalization.CultureInfo.InvariantCulture)
            });

            AddEnvelopeAsSignature(envelope);
        }

        public void AddMalformedSignature()
        {
            var blobBytes = Encoding.UTF8.GetBytes("not json {{{");
            var blobDigest = $"sha256:{HashAlgorithms.Sha256Hex(blobBytes)}";
            var sigManifestJson = BuildSigManifestJson(blobDigest, blobBytes.Length);
            var sigManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(Encoding.UTF8.GetBytes(sigManifestJson))}";
            _signatures.Add((sigManifestDigest, sigManifestJson, blobDigest, blobBytes));
        }

        public void AddEmptyLayerSignature()
        {
            var sigManifestJson = $$"""
                {
                  "schemaVersion": 2,
                  "mediaType": "application/vnd.oci.image.manifest.v1+json",
                  "artifactType": "application/vnd.sigil.signature.v1+json",
                  "config": {
                    "mediaType": "application/vnd.oci.empty.v1+json",
                    "digest": "sha256:empty",
                    "size": 2
                  },
                  "layers": []
                }
                """;
            var sigManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(Encoding.UTF8.GetBytes(sigManifestJson))}";
            _signatures.Add((sigManifestDigest, sigManifestJson, "", []));
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        private void AddEnvelopeAsSignature(SignatureEnvelope envelope)
        {
            var envelopeJson = JsonSerializer.Serialize(envelope, JsonOptions);
            var blobBytes = Encoding.UTF8.GetBytes(envelopeJson);
            var blobDigest = $"sha256:{HashAlgorithms.Sha256Hex(blobBytes)}";
            var sigManifestJson = BuildSigManifestJson(blobDigest, blobBytes.Length);
            var sigManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(Encoding.UTF8.GetBytes(sigManifestJson))}";
            _signatures.Add((sigManifestDigest, sigManifestJson, blobDigest, blobBytes));
        }

        private static string BuildSigManifestJson(string blobDigest, int blobSize) => $$"""
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "artifactType": "application/vnd.sigil.signature.v1+json",
              "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:44136fa355b311bfa706c3dba8b08a9b3bb45c4c5d86a99e340f0a2b9df3ac36",
                "size": 2
              },
              "layers": [
                {
                  "mediaType": "application/vnd.sigil.signature.v1+json",
                  "digest": "{{blobDigest}}",
                  "size": {{blobSize}}
                }
              ],
              "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "{{ManifestDigest}}",
                "size": {{ManifestBytes.Length}}
              }
            }
            """;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri?.PathAndQuery ?? "";

            // HEAD manifest
            if (request.Method == HttpMethod.Head && path.Contains("/manifests/"))
            {
                if (HeadFails)
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.Add("Docker-Content-Digest", ManifestDigest);
                response.Content = new StringContent("");
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(OciMediaTypes.OciManifestV1);
                response.Content.Headers.ContentLength = ManifestBytes.Length;
                return Task.FromResult(response);
            }

            // GET referrers
            if (request.Method == HttpMethod.Get && path.Contains("/referrers/"))
            {
                if (ReferrersNotSupported)
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

                var manifests = string.Join(",\n", _signatures.Select(s => $$"""
                    {
                      "mediaType": "application/vnd.oci.image.manifest.v1+json",
                      "digest": "{{s.Digest}}",
                      "size": 1000,
                      "artifactType": "application/vnd.sigil.signature.v1+json"
                    }
                    """));

                var indexJson = $$"""
                    {
                      "schemaVersion": 2,
                      "mediaType": "application/vnd.oci.image.index.v1+json",
                      "manifests": [{{manifests}}]
                    }
                    """;

                var resp = new HttpResponseMessage(HttpStatusCode.OK);
                resp.Content = new StringContent(indexJson);
                return Task.FromResult(resp);
            }

            // GET manifest (either image manifest or signature manifest)
            if (request.Method == HttpMethod.Get && path.Contains("/manifests/"))
            {
                // Check if it's a signature manifest
                foreach (var sig in _signatures)
                {
                    if (path.Contains(sig.Digest))
                    {
                        var resp = new HttpResponseMessage(HttpStatusCode.OK);
                        resp.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(sig.ManifestJson));
                        resp.Content.Headers.ContentType = new MediaTypeHeaderValue(OciMediaTypes.OciManifestV1);
                        resp.Headers.Add("Docker-Content-Digest", sig.Digest);
                        return Task.FromResult(resp);
                    }
                }

                // Image manifest
                var manifestToReturn = TamperManifest
                    ? Encoding.UTF8.GetBytes("""{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:tampered","size":1},"layers":[]}""")
                    : ManifestBytes;

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ByteArrayContent(manifestToReturn);
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(OciMediaTypes.OciManifestV1);
                response.Headers.Add("Docker-Content-Digest", ManifestDigest);
                return Task.FromResult(response);
            }

            // GET blob
            if (request.Method == HttpMethod.Get && path.Contains("/blobs/"))
            {
                if (BlobNotFound)
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

                foreach (var sig in _signatures)
                {
                    if (path.Contains(sig.BlobDigest))
                    {
                        var resp = new HttpResponseMessage(HttpStatusCode.OK);
                        resp.Content = new ByteArrayContent(sig.BlobBytes);
                        return Task.FromResult(resp);
                    }
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
