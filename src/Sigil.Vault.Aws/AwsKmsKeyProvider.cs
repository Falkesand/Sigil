using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Sigil.Crypto;

namespace Sigil.Vault.Aws;

public sealed class AwsKmsKeyProvider : IKeyProvider
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly IAmazonKeyManagementService _client;
    private bool _disposed;

    private AwsKmsKeyProvider(IAmazonKeyManagementService client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public static VaultResult<AwsKmsKeyProvider> Create()
    {
        var clientResult = AwsAuthFactory.CreateClient();
        if (!clientResult.IsSuccess)
        {
            return VaultResult<AwsKmsKeyProvider>.Fail(clientResult.ErrorKind, clientResult.ErrorMessage!);
        }

        return VaultResult<AwsKmsKeyProvider>.Ok(new AwsKmsKeyProvider(clientResult.Value!));
    }

    public async Task<VaultResult<ISigner>> GetSignerAsync(
        string keyReference,
        CancellationToken ct = default)
    {
        if (_disposed)
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.ConfigurationError,
                "AwsKmsKeyProvider has been disposed");
        }

        if (string.IsNullOrWhiteSpace(keyReference))
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.InvalidKeyReference,
                "Key reference cannot be null or empty");
        }

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(DefaultTimeout);

            var request = new GetPublicKeyRequest
            {
                KeyId = keyReference
            };

            var response = await _client.GetPublicKeyAsync(request, timeoutCts.Token).ConfigureAwait(false);

            var algorithm = AwsAlgorithmMap.FromAwsKeySpec(response.KeySpec);
            var publicKey = response.PublicKey.ToArray();

            var signer = new AwsKmsSigner(_client, keyReference, algorithm, publicKey);
            return VaultResult<ISigner>.Ok(signer);
        }
        catch (NotFoundException)
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.KeyNotFound,
                $"Key not found: {keyReference}");
        }
        catch (InvalidArnException)
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.InvalidKeyReference,
                $"Invalid key reference: {keyReference}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.SigningFailed,
                $"Failed to get AWS KMS signer: {ex.Message}");
        }
    }

    public async Task<VaultResult<byte[]>> GetPublicKeyAsync(
        string keyReference,
        CancellationToken ct = default)
    {
        var signerResult = await GetSignerAsync(keyReference, ct).ConfigureAwait(false);
        if (!signerResult.IsSuccess)
        {
            return VaultResult<byte[]>.Fail(signerResult.ErrorKind, signerResult.ErrorMessage!);
        }

        using var signer = signerResult.Value;
        return VaultResult<byte[]>.Ok(signer!.PublicKey);
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return default;
        }

        _disposed = true;

        if (_client is IDisposable disposable)
        {
            disposable.Dispose();
        }

        return default;
    }
}
