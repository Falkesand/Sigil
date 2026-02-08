using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Sigil.Crypto;
using VaultSharp;

namespace Sigil.Vault.HashiCorp;

public sealed class HashiCorpKeyProvider : IKeyProvider
{
    private IVaultClient? _client;

    private VaultResult<IVaultClient> EnsureClient()
    {
        if (_client is not null)
            return VaultResult<IVaultClient>.Ok(_client);

        var result = HashiCorpAuthFactory.CreateClient();
        if (result.IsSuccess)
            _client = result.Value;
        return result;
    }

    public async Task<VaultResult<ISigner>> GetSignerAsync(string keyReference, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyReference);

        var clientResult = EnsureClient();
        if (!clientResult.IsSuccess)
            return VaultResult<ISigner>.Fail(clientResult.ErrorKind, clientResult.ErrorMessage);

        var client = clientResult.Value;

        if (keyReference.StartsWith("transit/", StringComparison.OrdinalIgnoreCase))
        {
            var keyName = keyReference["transit/".Length..];
            return await CreateTransitSignerAsync(client, keyName, ct).ConfigureAwait(false);
        }

        if (keyReference.StartsWith("kv/", StringComparison.OrdinalIgnoreCase))
        {
            var kvPath = keyReference["kv/".Length..];
            return await CreateKvSignerAsync(client, kvPath, ct).ConfigureAwait(false);
        }

        // Default: assume transit
        return await CreateTransitSignerAsync(client, keyReference, ct).ConfigureAwait(false);
    }

    public async Task<VaultResult<byte[]>> GetPublicKeyAsync(string keyReference, CancellationToken ct = default)
    {
        var signerResult = await GetSignerAsync(keyReference, ct).ConfigureAwait(false);
        if (!signerResult.IsSuccess)
            return VaultResult<byte[]>.Fail(signerResult.ErrorKind, signerResult.ErrorMessage);

        using var signer = signerResult.Value;
        return VaultResult<byte[]>.Ok(signer.PublicKey);
    }

    private static async Task<VaultResult<ISigner>> CreateTransitSignerAsync(
        IVaultClient client, string keyName, CancellationToken ct)
    {
        try
        {
            var mountPath = HashiCorpAuthFactory.GetMountPath();
            var keyInfo = await client.V1.Secrets.Transit.ReadEncryptionKeyAsync(keyName, mountPath).ConfigureAwait(false);

            var keyType = keyInfo.Data.Type;
            var algorithm = HashiCorpAlgorithmMap.FromTransitKeyType(keyType);
            if (algorithm is null)
                return VaultResult<ISigner>.Fail(VaultErrorKind.UnsupportedAlgorithm,
                    $"Unsupported Transit key type: {keyType}");

            // Get the latest version's public key
            var latestVersion = keyInfo.Data.LatestVersion;
            var keys = keyInfo.Data.Keys;

            byte[]? publicKeyBytes = null;
            if (keys?.TryGetValue(latestVersion.ToString(CultureInfo.InvariantCulture), out var versionDataObj) == true)
            {
                var pem = ExtractPublicKeyPem(versionDataObj);
                if (!string.IsNullOrEmpty(pem))
                {
                    publicKeyBytes = ConvertPemToSpki(pem);
                }
            }

            if (publicKeyBytes is null)
                return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound,
                    $"Could not retrieve public key for Transit key '{keyName}'.");

            ISigner signer = new HashiCorpTransitSigner(client, keyName, mountPath, algorithm.Value, publicKeyBytes);
            return VaultResult<ISigner>.Ok(signer);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<ISigner>.Fail(VaultErrorKind.NetworkError, ex.Message);
        }
    }

    private static async Task<VaultResult<ISigner>> CreateKvSignerAsync(
        IVaultClient client, string kvPath, CancellationToken ct)
    {
        try
        {
            var kvResult = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(kvPath).ConfigureAwait(false);
            if (kvResult?.Data?.Data is null || !kvResult.Data.Data.TryGetValue("pem", out var pemObj))
                return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound,
                    $"KV path '{kvPath}' does not contain a 'pem' key.");

            var pemString = pemObj?.ToString();
            if (string.IsNullOrWhiteSpace(pemString))
                return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound,
                    $"KV path '{kvPath}' has empty PEM.");

            var pemChars = pemString.ToCharArray();
            try
            {
                var signer = SignerFactory.CreateFromPem(pemChars);
                return VaultResult<ISigner>.Ok(signer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    System.Runtime.InteropServices.MemoryMarshal.AsBytes(pemChars.AsSpan()));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<ISigner>.Fail(VaultErrorKind.NetworkError, ex.Message);
        }
    }

    internal static string? ExtractPublicKeyPem(object? versionData)
    {
        if (versionData is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object &&
                element.TryGetProperty("public_key", out var publicKeyProp))
            {
                return publicKeyProp.GetString();
            }

            if (element.ValueKind == JsonValueKind.String)
            {
                return element.GetString();
            }

            return null;
        }

        if (versionData is string s)
            return s;

        return null;
    }

    private static byte[] ConvertPemToSpki(string pem)
    {
        // Parse the PEM public key into SPKI bytes using ECDsa/RSA
        // Try EC first, then RSA
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa.ExportSubjectPublicKeyInfo();
        }
    }

    public ValueTask DisposeAsync()
    {
        _client = null;
        return ValueTask.CompletedTask;
    }
}
