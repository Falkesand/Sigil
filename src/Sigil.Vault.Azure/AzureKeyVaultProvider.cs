using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Vault.Azure;

/// <summary>
/// Azure Key Vault implementation of <see cref="IKeyProvider"/>.
/// </summary>
public sealed class AzureKeyVaultProvider : IKeyProvider
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly Uri _vaultUri;
    private readonly DefaultAzureCredential _credential;
    private readonly KeyClient _keyClient;

    private AzureKeyVaultProvider(Uri vaultUri, DefaultAzureCredential credential)
    {
        _vaultUri = vaultUri;
        _credential = credential;
        _keyClient = new KeyClient(vaultUri, credential);
    }

    /// <summary>
    /// Creates an <see cref="AzureKeyVaultProvider"/> using configuration from the environment.
    /// </summary>
    /// <returns>
    /// A <see cref="VaultResult{T}"/> containing the provider instance, or an error.
    /// </returns>
    public static VaultResult<AzureKeyVaultProvider> CreateFromEnvironment()
    {
        var authResult = AzureAuthFactory.CreateFromEnvironment();

        if (!authResult.IsSuccess)
        {
            return VaultResult<AzureKeyVaultProvider>.Fail(
                authResult.ErrorKind,
                authResult.ErrorMessage);
        }

        var (vaultUri, credential) = authResult.Value!;
        var provider = new AzureKeyVaultProvider(vaultUri, credential);

        return VaultResult<AzureKeyVaultProvider>.Ok(provider);
    }

    /// <summary>
    /// Gets a signer for the specified key reference.
    /// </summary>
    /// <param name="keyReference">
    /// The key reference: either a key name (resolved against the vault URL)
    /// or a full key identifier URL.
    /// </param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>
    /// A <see cref="VaultResult{T}"/> containing the signer instance, or an error.
    /// </returns>
    public async Task<VaultResult<ISigner>> GetSignerAsync(
        string keyReference,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(keyReference))
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.InvalidKeyReference,
                "Key reference cannot be null or empty.");
        }

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(DefaultTimeout);

            // Get the key from the vault
            Response<KeyVaultKey> keyResponse;

            if (Uri.TryCreate(keyReference, UriKind.Absolute, out var keyUri)
                && keyUri.Segments.Length >= 3
                && keyUri.Segments[1].TrimEnd('/').Equals("keys", StringComparison.OrdinalIgnoreCase))
            {
                // Full key identifier URL: https://vault.vault.azure.net/keys/<name>[/<version>]
                // Segments: ["/", "keys/", "<name>/", "<version>"]
                var keyName = keyUri.Segments[2].TrimEnd('/');
                var version = keyUri.Segments.Length >= 4
                    ? keyUri.Segments[3].TrimEnd('/')
                    : null;
                keyResponse = await _keyClient.GetKeyAsync(keyName, version, cancellationToken: timeoutCts.Token)
                    .ConfigureAwait(false);
            }
            else
            {
                // Key name only
                keyResponse = await _keyClient.GetKeyAsync(keyReference, cancellationToken: timeoutCts.Token)
                    .ConfigureAwait(false);
            }

            var key = keyResponse.Value;

            // Determine the signing algorithm from the key type
            if (!AzureAlgorithmMap.TryGetSigningAlgorithm(
                key.KeyType,
                key.Key.CurveName,
                out var algorithm))
            {
                return VaultResult<ISigner>.Fail(
                    VaultErrorKind.UnsupportedAlgorithm,
                    $"Unsupported key type: {key.KeyType}, curve: {key.Key.CurveName}");
            }

            // Extract the public key in SPKI format
            var publicKeyResult = ExtractPublicKey(key, algorithm);

            if (!publicKeyResult.IsSuccess)
            {
                return VaultResult<ISigner>.Fail(
                    publicKeyResult.ErrorKind,
                    publicKeyResult.ErrorMessage);
            }

            // Create a CryptographyClient for signing operations
            var cryptoClient = new CryptographyClient(key.Id, _credential);

            var signer = new AzureKeyVaultSigner(cryptoClient, algorithm, publicKeyResult.Value!);

            return VaultResult<ISigner>.Ok(signer);
        }
        catch (RequestFailedException ex)
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.KeyNotFound,
                $"Failed to retrieve key '{keyReference}' from Azure Key Vault: {ex.Message}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<ISigner>.Fail(
                VaultErrorKind.NetworkError,
                $"Unexpected error retrieving key '{keyReference}': {ex.Message}");
        }
    }

    /// <summary>
    /// Gets the public key for the specified key reference.
    /// </summary>
    /// <param name="keyReference">
    /// The key reference: either a key name (resolved against the vault URL)
    /// or a full key identifier URL.
    /// </param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>
    /// A <see cref="VaultResult{T}"/> containing the public key in SPKI format, or an error.
    /// </returns>
    public async Task<VaultResult<byte[]>> GetPublicKeyAsync(
        string keyReference,
        CancellationToken ct = default)
    {
        var signerResult = await GetSignerAsync(keyReference, ct).ConfigureAwait(false);

        if (!signerResult.IsSuccess)
        {
            return VaultResult<byte[]>.Fail(
                signerResult.ErrorKind,
                signerResult.ErrorMessage);
        }

        using var signer = signerResult.Value;
        return VaultResult<byte[]>.Ok(signer!.PublicKey);
    }

    /// <summary>
    /// Extracts the public key from an Azure Key Vault key in SPKI format.
    /// </summary>
    /// <param name="key">The Azure Key Vault key.</param>
    /// <param name="algorithm">The signing algorithm.</param>
    /// <returns>
    /// A <see cref="VaultResult{T}"/> containing the public key bytes, or an error.
    /// </returns>
    private static VaultResult<byte[]> ExtractPublicKey(KeyVaultKey key, SigningAlgorithm algorithm)
    {
        try
        {
            byte[] spki;

            if (algorithm == SigningAlgorithm.ECDsaP256 || algorithm == SigningAlgorithm.ECDsaP384 || algorithm == SigningAlgorithm.ECDsaP521)
            {
                using var ecdsa = key.Key.ToECDsa(includePrivateParameters: false);
                spki = ecdsa.ExportSubjectPublicKeyInfo();
            }
            else if (algorithm == SigningAlgorithm.Rsa)
            {
                using var rsa = key.Key.ToRSA(includePrivateParameters: false);
                spki = rsa.ExportSubjectPublicKeyInfo();
            }
            else
            {
                return VaultResult<byte[]>.Fail(
                    VaultErrorKind.UnsupportedAlgorithm,
                    $"Algorithm {algorithm} is not supported for public key extraction.");
            }

            return VaultResult<byte[]>.Ok(spki);
        }
        catch (Exception ex)
        {
            return VaultResult<byte[]>.Fail(
                VaultErrorKind.NetworkError,
                $"Failed to extract public key: {ex.Message}");
        }
    }

    /// <summary>
    /// Disposes resources used by this provider.
    /// </summary>
    public ValueTask DisposeAsync()
    {
        // DefaultAzureCredential may implement IDisposable in some SDK versions
        if (_credential is IDisposable disposable)
        {
            disposable.Dispose();
        }

        return default;
    }
}
