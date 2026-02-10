using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Sigil.Signing;

namespace Sigil.Transparency.Remote;

public sealed class SigilLogClient : IRemoteLog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;
    private readonly string _apiKey;

    public string LogUrl { get; }

    public SigilLogClient(string logUrl, string apiKey, HttpClient httpClient)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        ArgumentNullException.ThrowIfNull(httpClient);

        if (!Uri.TryCreate(logUrl, UriKind.Absolute, out var uri))
            throw new ArgumentException($"Invalid log URL: {logUrl}", nameof(logUrl));

        if (uri.Scheme != "https" && !IsLocalhost(uri))
            throw new ArgumentException("HTTPS is required for non-localhost log URLs.", nameof(logUrl));

        LogUrl = logUrl.TrimEnd('/');
        _apiKey = apiKey;
        _httpClient = httpClient;
        _ownsClient = false;
    }

    public SigilLogClient(string logUrl, string apiKey)
        : this(logUrl, apiKey, new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
        _ownsClient = true;
    }

    public async Task<RemoteLogResult<TransparencyReceipt>> AppendAsync(
        SignatureEntry entry, SubjectDescriptor subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(subject);

        var requestBody = new
        {
            keyId = entry.KeyId,
            algorithm = entry.Algorithm,
            publicKey = entry.PublicKey,
            signatureValue = entry.Value,
            artifactName = subject.Name,
            artifactDigest = subject.Digests.TryGetValue("sha256", out var sha256)
                ? "sha256:" + sha256
                : subject.Digests.First().Key + ":" + subject.Digests.First().Value,
            label = entry.Label
        };

        var json = JsonSerializer.Serialize(requestBody, JsonOptions);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{LogUrl}/api/v1/log/entries")
        {
            Content = content
        };
        request.Headers.Add("X-Api-Key", _apiKey);

        try
        {
            using var response = await _httpClient.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.AuthenticationFailed, "API key rejected by log server.");
            }

            if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.DuplicateEntry, "Entry already exists in the log.");
            }

            if (!response.IsSuccessStatusCode)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Log server returned HTTP {(int)response.StatusCode}.");
            }

            var responseJson = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ParseAppendResponse(responseJson);
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.Timeout, "Log append request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.NetworkError, $"Log append request failed: {ex.Message}");
        }
    }

    public async Task<RemoteLogResult<SignedCheckpoint>> GetCheckpointAsync(CancellationToken ct = default)
    {
        try
        {
            using var response = await _httpClient.GetAsync(
                $"{LogUrl}/api/v1/log/checkpoint", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return RemoteLogResult<SignedCheckpoint>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Checkpoint request returned HTTP {(int)response.StatusCode}.");
            }

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var checkpoint = JsonSerializer.Deserialize<SignedCheckpoint>(json);
            if (checkpoint is null)
            {
                return RemoteLogResult<SignedCheckpoint>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Failed to parse checkpoint response.");
            }

            return RemoteLogResult<SignedCheckpoint>.Ok(checkpoint);
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<SignedCheckpoint>.Fail(
                RemoteLogErrorKind.Timeout, "Checkpoint request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<SignedCheckpoint>.Fail(
                RemoteLogErrorKind.NetworkError, $"Checkpoint request failed: {ex.Message}");
        }
        catch (JsonException)
        {
            return RemoteLogResult<SignedCheckpoint>.Fail(
                RemoteLogErrorKind.InvalidResponse, "Checkpoint response is not valid JSON.");
        }
    }

    public async Task<RemoteLogResult<RemoteInclusionProof>> GetInclusionProofAsync(
        long leafIndex, CancellationToken ct = default)
    {
        try
        {
            using var response = await _httpClient.GetAsync(
                $"{LogUrl}/api/v1/log/proof/inclusion/{leafIndex}", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return RemoteLogResult<RemoteInclusionProof>.Fail(
                    RemoteLogErrorKind.ServerError,
                    $"Inclusion proof request returned HTTP {(int)response.StatusCode}.");
            }

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var proof = JsonSerializer.Deserialize<RemoteInclusionProof>(json);
            if (proof is null)
            {
                return RemoteLogResult<RemoteInclusionProof>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Failed to parse inclusion proof response.");
            }

            return RemoteLogResult<RemoteInclusionProof>.Ok(proof);
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<RemoteInclusionProof>.Fail(
                RemoteLogErrorKind.Timeout, "Inclusion proof request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<RemoteInclusionProof>.Fail(
                RemoteLogErrorKind.NetworkError, $"Inclusion proof request failed: {ex.Message}");
        }
        catch (JsonException)
        {
            return RemoteLogResult<RemoteInclusionProof>.Fail(
                RemoteLogErrorKind.InvalidResponse, "Inclusion proof response is not valid JSON.");
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
                    $"Public key request returned HTTP {(int)response.StatusCode}.");
            }

            var publicKey = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return RemoteLogResult<string>.Ok(publicKey.Trim());
        }
        catch (OperationCanceledException)
        {
            return RemoteLogResult<string>.Fail(
                RemoteLogErrorKind.Timeout, "Public key request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RemoteLogResult<string>.Fail(
                RemoteLogErrorKind.NetworkError, $"Public key request failed: {ex.Message}");
        }
    }

    private RemoteLogResult<TransparencyReceipt> ParseAppendResponse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (!root.TryGetProperty("logIndex", out var logIndexElement) ||
                !logIndexElement.TryGetInt64(out var logIndex))
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Response missing 'logIndex'.");
            }

            if (!root.TryGetProperty("signedCheckpoint", out var checkpointElement) ||
                checkpointElement.GetString() is not { } signedCheckpoint)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Response missing 'signedCheckpoint'.");
            }

            if (!root.TryGetProperty("inclusionProof", out var proofElement))
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Response missing 'inclusionProof'.");
            }

            var proof = JsonSerializer.Deserialize<RemoteInclusionProof>(proofElement.GetRawText());
            if (proof is null)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Failed to parse inclusion proof.");
            }

            var receipt = new TransparencyReceipt
            {
                LogUrl = LogUrl,
                LogIndex = logIndex,
                SignedCheckpoint = signedCheckpoint,
                InclusionProof = proof
            };

            return RemoteLogResult<TransparencyReceipt>.Ok(receipt);
        }
        catch (JsonException ex)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.InvalidResponse, $"Failed to parse append response: {ex.Message}");
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
