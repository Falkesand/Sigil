using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Sigil.Crypto;

namespace Sigil.Oci;

/// <summary>
/// Client for OCI Distribution Spec v2 registry operations.
/// HTTPS enforced for all registries except localhost.
/// </summary>
public sealed class OciRegistryClient : IDisposable
{
    private static readonly MediaTypeWithQualityHeaderValue OciManifestAccept = new(OciMediaTypes.OciManifestV1);
    private static readonly MediaTypeWithQualityHeaderValue DockerManifestAccept = new(OciMediaTypes.DockerManifestV2);
    private static readonly MediaTypeWithQualityHeaderValue OciIndexAccept = new(OciMediaTypes.OciImageIndex);
    private static readonly MediaTypeWithQualityHeaderValue DockerListAccept = new(OciMediaTypes.DockerManifestList);

    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _client;
    private readonly bool _ownsClient;
    private readonly string _baseUrl;

    public OciRegistryClient(ImageReference imageRef, RegistryCredentials? credentials = null,
        HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(imageRef);

        _baseUrl = imageRef.ApiEndpoint;
        _ownsClient = httpClient is null;

        if (httpClient is not null)
        {
            _client = httpClient;
        }
        else
        {
            var handler = new TokenAuthHandler(credentials);
            _client = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = DefaultTimeout
            };
        }
    }

    /// <summary>
    /// Checks if the registry supports the OCI Distribution Spec (/v2/ endpoint).
    /// </summary>
    public async Task<OciResult<bool>> CheckApiAsync(CancellationToken ct = default)
    {
        try
        {
            using var response = await _client.GetAsync($"{_baseUrl}/v2/", ct).ConfigureAwait(false);
            return response.IsSuccessStatusCode
                ? OciResult<bool>.Ok(true)
                : OciResult<bool>.Fail(OciErrorKind.RegistryError, $"Registry returned {(int)response.StatusCode}.");
        }
        catch (OperationCanceledException)
        {
            return OciResult<bool>.Fail(OciErrorKind.Timeout, "Registry check timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<bool>.Fail(OciErrorKind.NetworkError, $"Registry connection failed: {ex.Message}");
        }
    }

    /// <summary>
    /// HEAD request for a manifest, returning its digest, size, and media type.
    /// </summary>
    public async Task<OciResult<OciDescriptor>> HeadManifestAsync(
        string repository, string reference, CancellationToken ct = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Head,
                $"{_baseUrl}/v2/{repository}/manifests/{reference}");
            AddManifestAcceptHeaders(request);

            using var response = await _client.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return OciResult<OciDescriptor>.Fail(OciErrorKind.ManifestNotFound,
                    $"Manifest not found: {repository}:{reference}");

            response.EnsureSuccessStatusCode();

            if (!response.Headers.Contains("Docker-Content-Digest"))
                return OciResult<OciDescriptor>.Fail(OciErrorKind.RegistryError,
                    "Registry did not return Docker-Content-Digest header.");

            var digest = response.Headers.GetValues("Docker-Content-Digest").First();
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? OciMediaTypes.OciManifestV1;
            var size = response.Content.Headers.ContentLength ?? 0;

            return OciResult<OciDescriptor>.Ok(new OciDescriptor
            {
                MediaType = mediaType,
                Digest = digest,
                Size = size
            });
        }
        catch (OperationCanceledException)
        {
            return OciResult<OciDescriptor>.Fail(OciErrorKind.Timeout, "HEAD manifest timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<OciDescriptor>.Fail(OciErrorKind.NetworkError, $"HEAD manifest failed: {ex.Message}");
        }
    }

    /// <summary>
    /// GET manifest bytes + parsed manifest + descriptor.
    /// </summary>
    public async Task<OciResult<(byte[] Bytes, OciManifest Manifest, OciDescriptor Descriptor)>> GetManifestAsync(
        string repository, string reference, CancellationToken ct = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"{_baseUrl}/v2/{repository}/manifests/{reference}");
            AddManifestAcceptHeaders(request);

            using var response = await _client.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return OciResult<(byte[], OciManifest, OciDescriptor)>.Fail(
                    OciErrorKind.ManifestNotFound, $"Manifest not found: {repository}:{reference}");

            response.EnsureSuccessStatusCode();

            var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var parseResult = OciManifest.Deserialize(bytes);
            if (!parseResult.IsSuccess)
                return OciResult<(byte[], OciManifest, OciDescriptor)>.Fail(
                    parseResult.ErrorKind, parseResult.ErrorMessage);

            var digest = response.Headers.Contains("Docker-Content-Digest")
                ? response.Headers.GetValues("Docker-Content-Digest").First()
                : $"sha256:{HashAlgorithms.Sha256Hex(bytes)}";
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? OciMediaTypes.OciManifestV1;

            var descriptor = new OciDescriptor
            {
                MediaType = mediaType,
                Digest = digest,
                Size = bytes.Length
            };

            return OciResult<(byte[], OciManifest, OciDescriptor)>.Ok((bytes, parseResult.Value, descriptor));
        }
        catch (OperationCanceledException)
        {
            return OciResult<(byte[], OciManifest, OciDescriptor)>.Fail(OciErrorKind.Timeout, "GET manifest timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<(byte[], OciManifest, OciDescriptor)>.Fail(
                OciErrorKind.NetworkError, $"GET manifest failed: {ex.Message}");
        }
    }

    /// <summary>
    /// GET a blob by digest.
    /// </summary>
    public async Task<OciResult<byte[]>> GetBlobAsync(
        string repository, string digest, CancellationToken ct = default)
    {
        try
        {
            using var response = await _client.GetAsync(
                $"{_baseUrl}/v2/{repository}/blobs/{digest}", ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return OciResult<byte[]>.Fail(OciErrorKind.ManifestNotFound,
                    $"Blob not found: {digest}");

            response.EnsureSuccessStatusCode();
            var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            return OciResult<byte[]>.Ok(bytes);
        }
        catch (OperationCanceledException)
        {
            return OciResult<byte[]>.Fail(OciErrorKind.Timeout, "GET blob timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<byte[]>.Fail(OciErrorKind.NetworkError, $"GET blob failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Monolithic blob upload (POST + PUT).
    /// </summary>
    public async Task<OciResult<OciDescriptor>> UploadBlobAsync(
        string repository, byte[] data, CancellationToken ct = default)
    {
        try
        {
            var digest = $"sha256:{HashAlgorithms.Sha256Hex(data)}";

            // POST to initiate upload
            using var postResponse = await _client.PostAsync(
                $"{_baseUrl}/v2/{repository}/blobs/uploads/", null, ct).ConfigureAwait(false);

            if (!postResponse.IsSuccessStatusCode)
                return OciResult<OciDescriptor>.Fail(OciErrorKind.BlobUploadFailed,
                    $"Blob upload initiation failed: {(int)postResponse.StatusCode}");

            var location = postResponse.Headers.Location?.ToString();
            if (location is null)
                return OciResult<OciDescriptor>.Fail(OciErrorKind.BlobUploadFailed,
                    "Registry did not return Location header in blob upload response.");

            // Build PUT URL with digest
            var putUrl = location.Contains('?')
                ? $"{location}&digest={digest}"
                : $"{location}?digest={digest}";

            // Make absolute if relative
            if (!putUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                putUrl = $"{_baseUrl}{putUrl}";
            }
            else
            {
                // Validate absolute redirect URL stays on same host (prevent SSRF)
                if (Uri.TryCreate(putUrl, UriKind.Absolute, out var putUri) &&
                    Uri.TryCreate(_baseUrl, UriKind.Absolute, out var baseUri) &&
                    !string.Equals(putUri.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase))
                {
                    return OciResult<OciDescriptor>.Fail(OciErrorKind.BlobUploadFailed,
                        "Registry returned upload URL for a different host.");
                }
            }

            using var putContent = new ByteArrayContent(data);
            putContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

            using var putResponse = await _client.PutAsync(putUrl, putContent, ct).ConfigureAwait(false);

            if (!putResponse.IsSuccessStatusCode)
                return OciResult<OciDescriptor>.Fail(OciErrorKind.BlobUploadFailed,
                    $"Blob upload failed: {(int)putResponse.StatusCode}");

            return OciResult<OciDescriptor>.Ok(new OciDescriptor
            {
                MediaType = "application/octet-stream",
                Digest = digest,
                Size = data.Length
            });
        }
        catch (OperationCanceledException)
        {
            return OciResult<OciDescriptor>.Fail(OciErrorKind.Timeout, "Blob upload timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<OciDescriptor>.Fail(OciErrorKind.NetworkError, $"Blob upload failed: {ex.Message}");
        }
    }

    /// <summary>
    /// PUT a manifest by digest or tag.
    /// </summary>
    public async Task<OciResult<string>> PushManifestAsync(
        string repository, string reference, byte[] manifestBytes, string mediaType,
        CancellationToken ct = default)
    {
        try
        {
            using var content = new ByteArrayContent(manifestBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);

            using var response = await _client.PutAsync(
                $"{_baseUrl}/v2/{repository}/manifests/{reference}", content, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return OciResult<string>.Fail(OciErrorKind.RegistryError,
                    $"Push manifest failed: {(int)response.StatusCode}");

            var digest = response.Headers.Contains("Docker-Content-Digest")
                ? response.Headers.GetValues("Docker-Content-Digest").First()
                : $"sha256:{HashAlgorithms.Sha256Hex(manifestBytes)}";

            return OciResult<string>.Ok(digest);
        }
        catch (OperationCanceledException)
        {
            return OciResult<string>.Fail(OciErrorKind.Timeout, "Push manifest timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<string>.Fail(OciErrorKind.NetworkError, $"Push manifest failed: {ex.Message}");
        }
    }

    /// <summary>
    /// GET referrers for a manifest digest, optionally filtered by artifactType.
    /// Returns an OCI Image Index containing matching referrers.
    /// </summary>
    public async Task<OciResult<List<OciDescriptor>>> GetReferrersAsync(
        string repository, string digest, string? artifactType = null,
        CancellationToken ct = default)
    {
        try
        {
            var url = $"{_baseUrl}/v2/{repository}/referrers/{digest}";
            if (artifactType is not null)
                url = $"{url}?artifactType={Uri.EscapeDataString(artifactType)}";

            using var response = await _client.GetAsync(url, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return OciResult<List<OciDescriptor>>.Fail(OciErrorKind.ReferrersNotSupported,
                    "Referrers API not supported by this registry.");

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            // Referrers response is an OCI image index with "manifests" array,
            // not our OciManifest model (which requires config/layers). Parse directly.
            var referrers = ParseReferrersIndex(json);
            return OciResult<List<OciDescriptor>>.Ok(referrers);
        }
        catch (OperationCanceledException)
        {
            return OciResult<List<OciDescriptor>>.Fail(OciErrorKind.Timeout, "Referrers request timed out.");
        }
        catch (HttpRequestException ex)
        {
            return OciResult<List<OciDescriptor>>.Fail(OciErrorKind.NetworkError,
                $"Referrers request failed: {ex.Message}");
        }
    }

    private static List<OciDescriptor> ParseReferrersIndex(string json)
    {
        var result = new List<OciDescriptor>();
        using var doc = System.Text.Json.JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("manifests", out var manifests))
            return result;

        foreach (var m in manifests.EnumerateArray())
        {
            var mediaType = m.TryGetProperty("mediaType", out var mt) ? mt.GetString() : null;
            var digest = m.TryGetProperty("digest", out var d) ? d.GetString() : null;
            var size = m.TryGetProperty("size", out var s) ? s.GetInt64() : 0;
            var artifactType = m.TryGetProperty("artifactType", out var at) ? at.GetString() : null;

            if (mediaType is not null && digest is not null)
            {
                result.Add(new OciDescriptor
                {
                    MediaType = mediaType,
                    Digest = digest,
                    Size = size,
                    ArtifactType = artifactType
                });
            }
        }

        return result;
    }

    private static void AddManifestAcceptHeaders(HttpRequestMessage request)
    {
        request.Headers.Accept.Add(OciManifestAccept);
        request.Headers.Accept.Add(DockerManifestAccept);
        request.Headers.Accept.Add(OciIndexAccept);
        request.Headers.Accept.Add(DockerListAccept);
    }

    public void Dispose()
    {
        if (_ownsClient)
            _client.Dispose();
    }
}
