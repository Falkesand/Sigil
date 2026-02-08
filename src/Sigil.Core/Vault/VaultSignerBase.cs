using System.Text;
using Sigil.Crypto;

namespace Sigil.Vault;

/// <summary>
/// Abstract base for vault-backed signers where the private key stays in the vault.
/// Synchronous Sign() is not supported — all signing goes through SignAsync().
/// </summary>
public abstract class VaultSignerBase : ISigner
{
    public abstract SigningAlgorithm Algorithm { get; }
    public abstract byte[] PublicKey { get; }

    public byte[] Sign(byte[] data) =>
        throw new NotSupportedException("Vault signers require async signing via SignAsync().");

    public abstract ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default);

    public bool CanExportPrivateKey => false;

    public string ExportPublicKeyPem()
    {
        var spki = PublicKey;
        var base64 = Convert.ToBase64String(spki);
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN PUBLIC KEY-----");
        for (int i = 0; i < base64.Length; i += 64)
        {
            int len = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, len));
        }
        sb.Append("-----END PUBLIC KEY-----");
        return sb.ToString();
    }

    public byte[] ExportPrivateKeyPemBytes() =>
        throw new NotSupportedException("Vault signers do not expose private key material.");

    public byte[] ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char> password) =>
        throw new NotSupportedException("Vault signers do not expose private key material.");

    public abstract void Dispose();
}
