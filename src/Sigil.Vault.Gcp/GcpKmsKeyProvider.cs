using System.Security.Cryptography;
using Google.Cloud.Kms.V1;
using Sigil.Crypto;

namespace Sigil.Vault.Gcp;

public sealed class GcpKmsKeyProvider : IKeyProvider
{
    private readonly KeyManagementServiceClient _client;

    private GcpKmsKeyProvider(KeyManagementServiceClient client)
    {
        _client = client;
    }

    public static async Task<VaultResult<GcpKmsKeyProvider>> CreateAsync(CancellationToken ct = default)
    {
        var clientResult = await GcpAuthFactory.CreateClientAsync(ct).ConfigureAwait(false);
        if (!clientResult.IsSuccess)
        {
            return VaultResult<GcpKmsKeyProvider>.Fail(clientResult.ErrorKind, clientResult.ErrorMessage);
        }

        return VaultResult<GcpKmsKeyProvider>.Ok(new GcpKmsKeyProvider(clientResult.Value));
    }

    public static VaultResult<GcpKmsKeyProvider> Create()
    {
        var clientResult = GcpAuthFactory.CreateClient();
        if (!clientResult.IsSuccess)
        {
            return VaultResult<GcpKmsKeyProvider>.Fail(clientResult.ErrorKind, clientResult.ErrorMessage);
        }

        return VaultResult<GcpKmsKeyProvider>.Ok(new GcpKmsKeyProvider(clientResult.Value));
    }

    public async Task<VaultResult<ISigner>> GetSignerAsync(string keyReference, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(keyReference))
        {
            return VaultResult<ISigner>.Fail(VaultErrorKind.InvalidKeyReference, "Key reference cannot be null or empty");
        }

        try
        {
            var keyVersionName = CryptoKeyVersionName.Parse(keyReference);

            var publicKeyResponse = await _client.GetPublicKeyAsync(keyVersionName, ct).ConfigureAwait(false);

            var algorithmResult = GcpAlgorithmMap.FromGcpAlgorithm(publicKeyResponse.Algorithm);
            if (!algorithmResult.IsSuccess)
            {
                return VaultResult<ISigner>.Fail(algorithmResult.ErrorKind, algorithmResult.ErrorMessage);
            }

            var algorithm = algorithmResult.Value;

            var spkiBytes = algorithm switch
            {
                SigningAlgorithm.ECDsaP256 => ConvertPemToSpki<ECDsa>(publicKeyResponse.Pem),
                SigningAlgorithm.ECDsaP384 => ConvertPemToSpki<ECDsa>(publicKeyResponse.Pem),
                SigningAlgorithm.Rsa => ConvertPemToSpki<RSA>(publicKeyResponse.Pem),
                _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
            };

            if (spkiBytes is null)
            {
                return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound, "Failed to convert PEM to SPKI");
            }

            var signer = new GcpKmsSigner(_client, keyVersionName, algorithm, spkiBytes);
            return VaultResult<ISigner>.Ok(signer);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound, $"Failed to get signer: {ex.Message}");
        }
    }

    public async Task<VaultResult<byte[]>> GetPublicKeyAsync(string keyReference, CancellationToken ct = default)
    {
        var signerResult = await GetSignerAsync(keyReference, ct).ConfigureAwait(false);
        if (!signerResult.IsSuccess)
        {
            return VaultResult<byte[]>.Fail(signerResult.ErrorKind, signerResult.ErrorMessage);
        }

        using var signer = signerResult.Value;
        return VaultResult<byte[]>.Ok(signer!.PublicKey);
    }

    public ValueTask DisposeAsync()
    {
        return default;
    }

    private static byte[]? ConvertPemToSpki<T>(string pem) where T : AsymmetricAlgorithm
    {
        try
        {
            using var algorithm = typeof(T) == typeof(ECDsa)
                ? ECDsa.Create() as T
                : RSA.Create() as T;

            if (algorithm is null)
            {
                return null;
            }

            algorithm.ImportFromPem(pem);

            return algorithm switch
            {
                ECDsa ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
                RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }
}
