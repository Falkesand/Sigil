using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Oci;
using Sigil.Signing;

namespace Sigil.Integration.Tests;

/// <summary>
/// Integration tests that run a real in-process HTTP listener acting as an
/// OCI Distribution Spec v2 registry, then exercise the full sign → verify
/// round-trip through OciImageSigner and OciImageVerifier.
/// </summary>
public sealed class OciSignVerifyIntegrationTests : IAsyncLifetime, IDisposable
{
    private HttpListener? _listener;
    private Task? _serverTask;
    private CancellationTokenSource? _cts;
    private int _port;
    private string _baseUrl = "";
    private bool _disposed;

    // In-memory registry state
    private readonly ConcurrentDictionary<string, byte[]> _blobs = new();
    private readonly ConcurrentDictionary<string, byte[]> _manifests = new();
    private readonly ConcurrentDictionary<string, string> _manifestMediaTypes = new();

    // The "image" we're signing
    private static readonly string ImageManifestJson = """
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": 0
          },
          "layers": []
        }
        """;

    private static readonly byte[] ImageManifestBytes = Encoding.UTF8.GetBytes(ImageManifestJson);
    private static readonly string ImageManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(ImageManifestBytes)}";

    public async Task InitializeAsync()
    {
        // Find a free port
        using var tempListener = new TcpPortFinder();
        _port = tempListener.Port;
        _baseUrl = $"http://localhost:{_port}";

        // Store the image manifest
        _manifests[ImageManifestDigest] = ImageManifestBytes;
        _manifests["latest"] = ImageManifestBytes;
        _manifestMediaTypes[ImageManifestDigest] = "application/vnd.oci.image.manifest.v1+json";
        _manifestMediaTypes["latest"] = "application/vnd.oci.image.manifest.v1+json";

        _cts = new CancellationTokenSource();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"{_baseUrl}/");
        _listener.Start();

        _serverTask = Task.Run(() => RunServer(_cts.Token));

        // Give server a moment to start
        await Task.Delay(100);
    }

    public void Dispose()
    {
        if (_disposed) return;
        DisposeAsync().GetAwaiter().GetResult();
    }

    public async Task DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        try { _cts?.Cancel(); }
        catch (ObjectDisposedException) { /* already disposed */ }

        _listener?.Stop();
        try
        {
            if (_serverTask is not null)
                await _serverTask;
        }
        catch (OperationCanceledException) { }
        _listener?.Close();
        _cts?.Dispose();
    }

    [Fact]
    public async Task SignAndVerify_RoundTrip_EcdsaP256()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var imageRef = ImageReference.Parse($"localhost:{_port}/test/myapp:latest").Value;

        using var signClient = new OciRegistryClient(imageRef);
        var signResult = await OciImageSigner.SignAsync(signClient, imageRef, signer);

        Assert.True(signResult.IsSuccess, "Sign failed");
        Assert.StartsWith("sha256:", signResult.Value.ManifestDigest);
        Assert.Equal("ecdsa-p256", signResult.Value.Algorithm);

        // Now verify
        using var verifyClient = new OciRegistryClient(imageRef);
        var verifyResult = await OciImageVerifier.VerifyAsync(verifyClient, imageRef);

        Assert.True(verifyResult.IsSuccess, "Verify failed");
        Assert.Equal(1, verifyResult.Value.SignatureCount);
        Assert.True(verifyResult.Value.AllSignaturesValid);
        Assert.Equal(ImageManifestDigest, verifyResult.Value.ManifestDigest);
    }

    [Fact]
    public async Task SignAndVerify_RoundTrip_EcdsaP384()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var imageRef = ImageReference.Parse($"localhost:{_port}/test/myapp:latest").Value;

        using var signClient = new OciRegistryClient(imageRef);
        var signResult = await OciImageSigner.SignAsync(signClient, imageRef, signer);

        Assert.True(signResult.IsSuccess, "Sign failed");
        Assert.Equal("ecdsa-p384", signResult.Value.Algorithm);

        using var verifyClient = new OciRegistryClient(imageRef);
        var verifyResult = await OciImageVerifier.VerifyAsync(verifyClient, imageRef);

        Assert.True(verifyResult.IsSuccess, "Verify failed");
        Assert.True(verifyResult.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task SignAndVerify_RoundTrip_RsaPss()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.Rsa);
        var imageRef = ImageReference.Parse($"localhost:{_port}/test/myapp:latest").Value;

        using var signClient = new OciRegistryClient(imageRef);
        var signResult = await OciImageSigner.SignAsync(signClient, imageRef, signer);

        Assert.True(signResult.IsSuccess, "Sign failed");
        Assert.Equal("rsa-pss-sha256", signResult.Value.Algorithm);

        using var verifyClient = new OciRegistryClient(imageRef);
        var verifyResult = await OciImageVerifier.VerifyAsync(verifyClient, imageRef);

        Assert.True(verifyResult.IsSuccess, "Verify failed");
        Assert.True(verifyResult.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task MultipleSignatures_AllVerified()
    {
        var imageRef = ImageReference.Parse($"localhost:{_port}/test/myapp:latest").Value;

        // Sign with two different keys
        using var signer1 = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signClient1 = new OciRegistryClient(imageRef);
        var result1 = await OciImageSigner.SignAsync(signClient1, imageRef, signer1, label: "ci-build");
        Assert.True(result1.IsSuccess, "Sign 1 failed");

        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        using var signClient2 = new OciRegistryClient(imageRef);
        var result2 = await OciImageSigner.SignAsync(signClient2, imageRef, signer2, label: "security-review");
        Assert.True(result2.IsSuccess, "Sign 2 failed");

        // Verify finds both
        using var verifyClient = new OciRegistryClient(imageRef);
        var verifyResult = await OciImageVerifier.VerifyAsync(verifyClient, imageRef);

        Assert.True(verifyResult.IsSuccess, "Verify failed");
        Assert.Equal(2, verifyResult.Value.SignatureCount);
        Assert.True(verifyResult.Value.AllSignaturesValid);
    }

    [Fact]
    public async Task SignWithLabel_LabelPreservedInVerification()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var imageRef = ImageReference.Parse($"localhost:{_port}/test/myapp:latest").Value;

        using var signClient = new OciRegistryClient(imageRef);
        var signResult = await OciImageSigner.SignAsync(signClient, imageRef, signer, label: "release-v1");
        Assert.True(signResult.IsSuccess);

        using var verifyClient = new OciRegistryClient(imageRef);
        var verifyResult = await OciImageVerifier.VerifyAsync(verifyClient, imageRef);

        Assert.True(verifyResult.IsSuccess);
        var sigResult = verifyResult.Value.SignatureResults[0];
        Assert.Equal("release-v1", sigResult.Signatures[0].Label);
    }

    [Fact]
    public async Task NoSignatures_VerifyReturnsSignatureNotFound()
    {
        // Use a different image ref so there are no pre-existing signatures
        var imageRef = ImageReference.Parse($"localhost:{_port}/test/unsigned:latest").Value;

        // Store a manifest for this image too
        _manifests["unsigned-latest"] = ImageManifestBytes;
        _manifestMediaTypes["unsigned-latest"] = "application/vnd.oci.image.manifest.v1+json";

        using var client = new OciRegistryClient(imageRef);
        var result = await OciImageVerifier.VerifyAsync(client, imageRef);

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.SignatureNotFound, result.ErrorKind);
    }

    private async Task RunServer(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var context = await _listener!.GetContextAsync().WaitAsync(ct);
                _ = Task.Run(() => HandleRequest(context), CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) { break; }
            catch (ObjectDisposedException) { break; }
        }
    }

    private void HandleRequest(HttpListenerContext context)
    {
        try
        {
            var path = context.Request.Url?.AbsolutePath ?? "";
            var method = context.Request.HttpMethod;

            // /v2/ check
            if (path == "/v2/" || path == "/v2")
            {
                context.Response.StatusCode = 200;
                context.Response.Close();
                return;
            }

            // HEAD /v2/<name>/manifests/<ref>
            if (method == "HEAD" && path.Contains("/manifests/"))
            {
                HandleHeadManifest(context, path);
                return;
            }

            // GET /v2/<name>/referrers/<digest>
            if (method == "GET" && path.Contains("/referrers/"))
            {
                HandleGetReferrers(context, path);
                return;
            }

            // GET /v2/<name>/manifests/<ref>
            if (method == "GET" && path.Contains("/manifests/"))
            {
                HandleGetManifest(context, path);
                return;
            }

            // POST /v2/<name>/blobs/uploads/
            if (method == "POST" && path.Contains("/blobs/uploads"))
            {
                HandlePostBlobUpload(context);
                return;
            }

            // PUT /v2/<name>/blobs/uploads/<session>?digest=...
            if (method == "PUT" && path.Contains("/blobs/uploads/"))
            {
                HandlePutBlob(context);
                return;
            }

            // PUT /v2/<name>/manifests/<ref>
            if (method == "PUT" && path.Contains("/manifests/"))
            {
                HandlePutManifest(context, path);
                return;
            }

            // GET /v2/<name>/blobs/<digest>
            if (method == "GET" && path.Contains("/blobs/"))
            {
                HandleGetBlob(context, path);
                return;
            }

            context.Response.StatusCode = 404;
            context.Response.Close();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            try { context.Response.StatusCode = 500; context.Response.Close(); }
            catch (Exception inner) when (inner is not OutOfMemoryException) { /* best effort */ }
        }
    }

    private void HandleHeadManifest(HttpListenerContext context, string path)
    {
        var reference = path.Split("/manifests/").Last();
        var (bytes, mediaType) = ResolveManifest(reference, path);
        if (bytes is null)
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
            return;
        }

        var digest = $"sha256:{HashAlgorithms.Sha256Hex(bytes)}";
        context.Response.StatusCode = 200;
        context.Response.Headers["Docker-Content-Digest"] = digest;
        context.Response.ContentType = mediaType ?? "application/vnd.oci.image.manifest.v1+json";
        context.Response.ContentLength64 = bytes.Length;
        context.Response.Close();
    }

    private void HandleGetManifest(HttpListenerContext context, string path)
    {
        var reference = path.Split("/manifests/").Last();
        var (bytes, mediaType) = ResolveManifest(reference, path);
        if (bytes is null)
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
            return;
        }

        var digest = $"sha256:{HashAlgorithms.Sha256Hex(bytes)}";
        context.Response.StatusCode = 200;
        context.Response.Headers["Docker-Content-Digest"] = digest;
        context.Response.ContentType = mediaType ?? "application/vnd.oci.image.manifest.v1+json";
        context.Response.OutputStream.Write(bytes, 0, bytes.Length);
        context.Response.Close();
    }

    private void HandlePutManifest(HttpListenerContext context, string path)
    {
        using var ms = new MemoryStream();
        context.Request.InputStream.CopyTo(ms);
        var bytes = ms.ToArray();
        var digest = $"sha256:{HashAlgorithms.Sha256Hex(bytes)}";
        var mediaType = context.Request.ContentType ?? "application/vnd.oci.image.manifest.v1+json";

        _manifests[digest] = bytes;
        _manifestMediaTypes[digest] = mediaType;

        context.Response.StatusCode = 201;
        context.Response.Headers["Docker-Content-Digest"] = digest;
        context.Response.Close();
    }

    private void HandleGetReferrers(HttpListenerContext context, string path)
    {
        var digest = path.Split("/referrers/").Last();

        // Find all manifests that have `subject.digest` matching this digest
        var referrers = new List<string>();
        foreach (var (key, value) in _manifests)
        {
            if (!key.StartsWith("sha256:", StringComparison.Ordinal))
                continue;
            if (value == ImageManifestBytes)
                continue; // Skip the image itself

            try
            {
                using var doc = JsonDocument.Parse(value);
                var root = doc.RootElement;
                if (root.TryGetProperty("subject", out var subject) &&
                    subject.TryGetProperty("digest", out var subDigest) &&
                    string.Equals(subDigest.GetString(), digest, StringComparison.Ordinal))
                {
                    var artifactType = root.TryGetProperty("artifactType", out var at) ? at.GetString() : null;
                    var mt = root.TryGetProperty("mediaType", out var m) ? m.GetString() : "application/vnd.oci.image.manifest.v1+json";

                    // Apply artifactType filter from query string
                    var query = context.Request.Url?.Query ?? "";
                    if (query.Contains("artifactType="))
                    {
                        var filterType = Uri.UnescapeDataString(
                            query.Split("artifactType=").Last().Split('&').First());
                        if (!string.Equals(artifactType, filterType, StringComparison.Ordinal))
                            continue;
                    }

                    referrers.Add($$"""
                        {
                          "mediaType": "{{mt}}",
                          "digest": "{{key}}",
                          "size": {{value.Length}},
                          "artifactType": "{{artifactType}}"
                        }
                        """);
                }
            }
            catch (JsonException) { /* skip non-JSON manifests */ }
        }

        var indexJson = $$"""
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.index.v1+json",
              "manifests": [{{string.Join(",", referrers)}}]
            }
            """;

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/vnd.oci.image.index.v1+json";
        var responseBytes = Encoding.UTF8.GetBytes(indexJson);
        context.Response.OutputStream.Write(responseBytes, 0, responseBytes.Length);
        context.Response.Close();
    }

    private static void HandlePostBlobUpload(HttpListenerContext context)
    {
        var sessionId = Guid.NewGuid().ToString("N");
        context.Response.StatusCode = 202;
        context.Response.Headers["Location"] = $"/v2/test/blobs/uploads/{sessionId}";
        context.Response.Close();
    }

    private void HandlePutBlob(HttpListenerContext context)
    {
        using var ms = new MemoryStream();
        context.Request.InputStream.CopyTo(ms);
        var data = ms.ToArray();

        var query = context.Request.Url?.Query ?? "";
        var digest = query.Contains("digest=")
            ? Uri.UnescapeDataString(query.Split("digest=").Last().Split('&').First())
            : $"sha256:{HashAlgorithms.Sha256Hex(data)}";

        _blobs[digest] = data;

        context.Response.StatusCode = 201;
        context.Response.Headers["Docker-Content-Digest"] = digest;
        context.Response.Close();
    }

    private void HandleGetBlob(HttpListenerContext context, string path)
    {
        var digest = path.Split("/blobs/").Last();
        if (_blobs.TryGetValue(digest, out var data))
        {
            context.Response.StatusCode = 200;
            context.Response.OutputStream.Write(data, 0, data.Length);
            context.Response.Close();
        }
        else
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
        }
    }

    private (byte[]? Bytes, string? MediaType) ResolveManifest(string reference, string path)
    {
        // Try exact reference match
        if (_manifests.TryGetValue(reference, out var bytes))
        {
            _manifestMediaTypes.TryGetValue(reference, out var mt);
            return (bytes, mt);
        }

        // For tag references, return the image manifest
        if (!reference.StartsWith("sha256:", StringComparison.Ordinal))
        {
            return (ImageManifestBytes, "application/vnd.oci.image.manifest.v1+json");
        }

        return (null, null);
    }

    /// <summary>
    /// Helper to find a free TCP port.
    /// </summary>
    private sealed class TcpPortFinder : IDisposable
    {
        private readonly System.Net.Sockets.TcpListener _listener;
        public int Port { get; }

        public TcpPortFinder()
        {
            _listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _listener.Stop();
        }

        public void Dispose() { }
    }
}
