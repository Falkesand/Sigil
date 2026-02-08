using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Sigil.Timestamping;

/// <summary>
/// HTTP client for RFC 3161 Timestamp Authority (TSA) requests.
/// </summary>
public sealed class TsaClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;

    public TsaClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
        _ownsHttpClient = false;
    }

    public TsaClient() : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) }, ownsClient: true)
    {
    }

    private TsaClient(HttpClient httpClient, bool ownsClient)
    {
        _httpClient = httpClient;
        _ownsHttpClient = ownsClient;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    public async Task<TimestampResult<byte[]>> RequestTimestampAsync(
        Uri tsaUri, byte[] signatureBytes, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tsaUri);
        ArgumentNullException.ThrowIfNull(signatureBytes);

        try
        {
            var hash = SHA256.HashData(signatureBytes);
            var nonce = RandomNumberGenerator.GetBytes(8);

            var request = Rfc3161TimestampRequest.CreateFromHash(
                hash,
                HashAlgorithmName.SHA256,
                requestedPolicyId: null,
                nonce: new ReadOnlyMemory<byte>(nonce),
                requestSignerCertificates: true,
                extensions: null);

            var encoded = request.Encode();

            using var content = new ByteArrayContent(encoded);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");

            using var response = await _httpClient.PostAsync(tsaUri, content, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return TimestampResult<byte[]>.Fail(TimestampErrorKind.NetworkError,
                    $"TSA returned HTTP {(int)response.StatusCode}.");
            }

            var responseBytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

            var token = request.ProcessResponse(responseBytes, out _);
            return TimestampResult<byte[]>.Ok(token.AsSignedCms().Encode());
        }
        catch (OperationCanceledException)
        {
            return TimestampResult<byte[]>.Fail(TimestampErrorKind.Timeout,
                "Timestamp request was cancelled or timed out.");
        }
        catch (HttpRequestException ex)
        {
            return TimestampResult<byte[]>.Fail(TimestampErrorKind.NetworkError,
                $"HTTP request to TSA failed: {ex.Message}");
        }
        catch (CryptographicException ex)
        {
            return TimestampResult<byte[]>.Fail(TimestampErrorKind.InvalidResponse,
                $"Failed to process TSA response: {ex.Message}");
        }
    }
}
