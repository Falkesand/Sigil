using System.Security.Cryptography;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Sigil.Crypto;

namespace Sigil.Vault.Gcp;

internal sealed class GcpKmsSigner : VaultSignerBase
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly KeyManagementServiceClient _client;
    private readonly CryptoKeyVersionName _keyVersionName;

    public override SigningAlgorithm Algorithm { get; }
    public override byte[] PublicKey { get; }

    public GcpKmsSigner(
        KeyManagementServiceClient client,
        CryptoKeyVersionName keyVersionName,
        SigningAlgorithm algorithm,
        byte[] publicKey)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _keyVersionName = keyVersionName ?? throw new ArgumentNullException(nameof(keyVersionName));
        Algorithm = algorithm;
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public override async ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        var digest = Algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => new Digest { Sha256 = ByteString.CopyFrom(SHA256.HashData(data)) },
            SigningAlgorithm.Rsa => new Digest { Sha256 = ByteString.CopyFrom(SHA256.HashData(data)) },
            SigningAlgorithm.ECDsaP384 => new Digest { Sha384 = ByteString.CopyFrom(SHA384.HashData(data)) },
            _ => throw new NotSupportedException($"Algorithm {Algorithm} is not supported for GCP KMS signing")
        };

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(DefaultTimeout);

        var response = await _client.AsymmetricSignAsync(
            _keyVersionName,
            digest,
            timeoutCts.Token).ConfigureAwait(false);

        return response.Signature.ToByteArray();
    }

    public override void Dispose()
    {
        // KeyManagementServiceClient doesn't implement IDisposable, nothing to dispose
    }
}
