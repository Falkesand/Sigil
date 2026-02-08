using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Keys.Cryptography;
using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Vault.Azure;

/// <summary>
/// A signer implementation that uses Azure Key Vault for signing operations.
/// </summary>
internal sealed class AzureKeyVaultSigner : VaultSignerBase
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly CryptographyClient _cryptoClient;
    private readonly SignatureAlgorithm _azureAlgorithm;
    private readonly SigningAlgorithm _algorithm;
    private readonly byte[] _publicKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultSigner"/> class.
    /// </summary>
    /// <param name="cryptoClient">The cryptography client for signing operations.</param>
    /// <param name="algorithm">The Sigil signing algorithm.</param>
    /// <param name="publicKey">The public key in SPKI format.</param>
    public AzureKeyVaultSigner(
        CryptographyClient cryptoClient,
        SigningAlgorithm algorithm,
        byte[] publicKey)
    {
        _cryptoClient = cryptoClient ?? throw new ArgumentNullException(nameof(cryptoClient));
        _algorithm = algorithm;
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));

        if (!AzureAlgorithmMap.TryGetAzureAlgorithm(algorithm, out var azureAlgorithm))
        {
            throw new ArgumentException(
                $"Algorithm {algorithm} is not supported by Azure Key Vault.",
                nameof(algorithm));
        }

        _azureAlgorithm = azureAlgorithm.Value;
    }

    public override SigningAlgorithm Algorithm => _algorithm;
    public override byte[] PublicKey => _publicKey;

    /// <summary>
    /// Signs data asynchronously using the Azure Key Vault key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The signature bytes.</returns>
    public override async ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(DefaultTimeout);

            // Azure Key Vault's SignDataAsync handles hashing internally based on the algorithm
            var result = await _cryptoClient.SignDataAsync(_azureAlgorithm, data, timeoutCts.Token)
                .ConfigureAwait(false);

            return result.Signature;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new CryptographicException(
                $"Failed to sign data using Azure Key Vault: {ex.Message}",
                ex);
        }
    }

    /// <summary>
    /// Disposes resources used by this signer.
    /// </summary>
    public override void Dispose()
    {
        // CryptographyClient does not implement IDisposable as of current SDK version
        // Nothing to dispose
    }
}
