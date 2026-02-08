using Sigil.Crypto;
using VaultSharp;
using VaultSharp.V1.SecretsEngines.Transit;

namespace Sigil.Vault.HashiCorp;

public sealed class HashiCorpTransitSigner : VaultSignerBase
{
    private readonly IVaultClient _client;
    private readonly string _keyName;
    private readonly string _mountPath;
    private readonly SigningAlgorithm _algorithm;
    private readonly byte[] _publicKey;

    internal HashiCorpTransitSigner(
        IVaultClient client,
        string keyName,
        string mountPath,
        SigningAlgorithm algorithm,
        byte[] publicKey)
    {
        _client = client;
        _keyName = keyName;
        _mountPath = mountPath;
        _algorithm = algorithm;
        _publicKey = publicKey;
    }

    public override SigningAlgorithm Algorithm => _algorithm;
    public override byte[] PublicKey => _publicKey;

    public override async ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        var base64Input = Convert.ToBase64String(data);
        var hashAlgorithm = HashiCorpAlgorithmMap.ToTransitHashAlgorithm(_algorithm);
        var signatureAlgorithm = HashiCorpAlgorithmMap.ToTransitSignatureAlgorithm(_algorithm);

        var options = new SignRequestOptions
        {
            HashAlgorithm = hashAlgorithm,
            MarshalingAlgorithm = MarshalingAlgorithm.jws,
            PreHashed = false,
            Base64EncodedInput = base64Input
        };

        if (signatureAlgorithm is not null)
        {
            options.SignatureAlgorithm = signatureAlgorithm;
            // Use salt=hash length for PSS to match .NET RSASignaturePadding.Pss
            options.SaltLength = "hash";
        }

        var result = await _client.V1.Secrets.Transit.SignDataAsync(
            _keyName,
            options,
            _mountPath).ConfigureAwait(false);

        // Transit returns "vault:v1:<base64url>" — strip the prefix
        var signatureValue = result.Data.Signature;
        var lastColon = signatureValue.LastIndexOf(':');
        var base64UrlSig = lastColon >= 0 ? signatureValue[(lastColon + 1)..] : signatureValue;

        return DecodeBase64Url(base64UrlSig);
    }

    internal static byte[] DecodeBase64Url(string base64Url)
    {
        // Convert base64url to standard base64: replace URL-safe chars and add padding
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
        if (padding > 0)
            base64 = string.Concat(base64, new string('=', padding));
        return Convert.FromBase64String(base64);
    }

    public override void Dispose()
    {
        // VaultClient doesn't implement IDisposable
    }
}
