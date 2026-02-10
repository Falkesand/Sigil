using System.Text;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Signing;

namespace Sigil.Transparency.Remote;

public sealed class RekorClient : IRemoteLog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    public string LogUrl { get; }

    public RekorClient(string logUrl, HttpClient httpClient)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logUrl);
        ArgumentNullException.ThrowIfNull(httpClient);

        if (!Uri.TryCreate(logUrl, UriKind.Absolute, out var uri))
            throw new ArgumentException($"Invalid Rekor URL: {logUrl}", nameof(logUrl));

        if (uri.Scheme != "https" && !IsLocalhost(uri))
            throw new ArgumentException("HTTPS is required for non-localhost Rekor URLs.", nameof(logUrl));

        LogUrl = logUrl.TrimEnd('/');
        _httpClient = httpClient;
        _ownsClient = false;
    }

    public RekorClient(string logUrl = "https://rekor.sigstore.dev")
        : this(logUrl, new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
        _ownsClient = true;
    }

    public async Task<RemoteLogResult<TransparencyReceipt>> AppendAsync(
        SignatureEntry entry, SubjectDescriptor subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(subject);

        // Build hashedrekord v0.0.1 payload
        var artifactDigest = subject.Digests.TryGetValue("sha256", out var sha256)
            ? sha256
            : null;

        if (artifactDigest is null)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.InvalidResponse,
                "Subject must have a sha256 digest for Rekor hashedrekord.");
        }

        var publicKeyPem = RekorEntryParser.SpkiToPem(entry.PublicKey);
        var publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyPem));

        var hashedrekord = new
        {
            apiVersion = "0.0.1",
            kind = "hashedrekord",
            spec = new
            {
                data = new
                {
                    hash = new
                    {
                        algorithm = "sha256",
                        value = artifactDigest
                    }
                },
                signature = new
                {
                    content = entry.Value,
                    publicKey = new
                    {
                        content = publicKeyBase64
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(hashedrekord, JsonOptions);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            using var response = await _httpClient.PostAsync(
                $"{LogUrl}/api/v1/log/entries", content, ct).ConfigureAwait(false);

            if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                // Rekor returns 409 with the existing entry in the body
                var conflictJson = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return RekorEntryParser.ParseResponse(conflictJson, LogUrl);
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                if (errorBody.Length > 500)
                    errorBody = errorBody[..500] + "...(truncated)";
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Rekor returned HTTP {(int)response.StatusCode}: {errorBody}");
            }

            var responseJson = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return RekorEntryParser.ParseResponse(responseJson, LogUrl);
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.Timeout, "Rekor request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.NetworkError, $"Rekor request failed: {ex.Message}");
        }
    }

    public async Task<RemoteLogResult<SignedCheckpoint>> GetCheckpointAsync(CancellationToken ct = default)
    {
        try
        {
            using var response = await _httpClient.GetAsync(
                $"{LogUrl}/api/v1/log", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return RemoteLogResult<SignedCheckpoint>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Rekor log info returned HTTP {(int)response.StatusCode}.");
            }

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var treeSize = root.TryGetProperty("treeSize", out var ts) && ts.TryGetInt64(out var tsVal) ? tsVal : 0;
            var rootHash = root.TryGetProperty("rootHash", out var rh) ? rh.GetString() ?? "" : "";
            var signedTreeHead = root.TryGetProperty("signedTreeHead", out var sth) ? sth.GetRawText() : "";

            var checkpoint = new SignedCheckpoint
            {
                TreeSize = treeSize,
                RootHash = rootHash,
                Timestamp = DateTime.UtcNow.ToString("o"),
                Signature = signedTreeHead
            };

            return RemoteLogResult<SignedCheckpoint>.Ok(checkpoint);
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<SignedCheckpoint>.Fail(
                RemoteLogErrorKind.Timeout, "Rekor checkpoint request timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<SignedCheckpoint>.Fail(
                RemoteLogErrorKind.NetworkError, $"Rekor checkpoint request failed: {ex.Message}");
        }
        catch (JsonException)
        {
            return RemoteLogResult<SignedCheckpoint>.Fail(
                RemoteLogErrorKind.InvalidResponse, "Rekor log info is not valid JSON.");
        }
    }

    public async Task<RemoteLogResult<RemoteInclusionProof>> GetInclusionProofAsync(
        long leafIndex, CancellationToken ct = default)
    {
        try
        {
            // Rekor doesn't have a direct inclusion proof endpoint by index.
            // We first get the entry to find its UUID, then get proof via tree info.
            using var response = await _httpClient.GetAsync(
                $"{LogUrl}/api/v1/log/entries?logIndex={leafIndex}", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return RemoteLogResult<RemoteInclusionProof>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Rekor entry lookup returned HTTP {(int)response.StatusCode}.");
            }

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var receiptResult = RekorEntryParser.ParseResponse(json, LogUrl);
            if (!receiptResult.IsSuccess)
            {
                return RemoteLogResult<RemoteInclusionProof>.Fail(
                    receiptResult.ErrorKind, receiptResult.ErrorMessage);
            }

            return RemoteLogResult<RemoteInclusionProof>.Ok(receiptResult.Value.InclusionProof);
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<RemoteInclusionProof>.Fail(
                RemoteLogErrorKind.Timeout, "Rekor inclusion proof request timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<RemoteInclusionProof>.Fail(
                RemoteLogErrorKind.NetworkError, $"Rekor inclusion proof request failed: {ex.Message}");
        }
    }

    public async Task<RemoteLogResult<string>> GetPublicKeyAsync(CancellationToken ct = default)
    {
        try
        {
            using var response = await _httpClient.GetAsync(
                $"{LogUrl}/api/v1/log/publicKey", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return RemoteLogResult<string>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Rekor public key request returned HTTP {(int)response.StatusCode}.");
            }

            var publicKey = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return RemoteLogResult<string>.Ok(publicKey.Trim());
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<string>.Fail(
                RemoteLogErrorKind.Timeout, "Rekor public key request timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<string>.Fail(
                RemoteLogErrorKind.NetworkError, $"Rekor public key request failed: {ex.Message}");
        }
    }

    private static bool IsLocalhost(Uri uri)
    {
        return string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) ||
               uri.Host == "127.0.0.1" ||
               uri.Host == "::1";
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }
    }
}
