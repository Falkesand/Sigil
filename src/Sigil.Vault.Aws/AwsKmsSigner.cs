using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Sigil.Crypto;

namespace Sigil.Vault.Aws;

internal sealed class AwsKmsSigner : VaultSignerBase
{
    private readonly IAmazonKeyManagementService _client;
    private readonly string _keyId;
    private readonly SigningAlgorithm _algorithm;
    private readonly byte[] _publicKey;

    public AwsKmsSigner(
        IAmazonKeyManagementService client,
        string keyId,
        SigningAlgorithm algorithm,
        byte[] publicKey)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _keyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
        _algorithm = algorithm;
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public override SigningAlgorithm Algorithm => _algorithm;
    public override byte[] PublicKey => _publicKey;

    public override async ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        using var messageStream = new MemoryStream(data);
        var request = new SignRequest
        {
            KeyId = _keyId,
            Message = messageStream,
            MessageType = MessageType.RAW,
            SigningAlgorithm = AwsAlgorithmMap.ToAwsAlgorithm(_algorithm)
        };

        var response = await _client.SignAsync(request, cancellationToken).ConfigureAwait(false);
        return response.Signature.ToArray();
    }

    public override void Dispose()
    {
        // Client is owned by AwsKmsKeyProvider, not disposed here
    }
}
