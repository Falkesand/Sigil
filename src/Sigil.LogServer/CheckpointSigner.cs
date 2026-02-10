using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;

namespace Sigil.LogServer;

public sealed class CheckpointSigner : IDisposable
{
    private readonly ECDsa _key;
    private readonly byte[] _publicKeySpki;

    public CheckpointSigner(ECDsa key)
    {
        _key = key;
        _publicKeySpki = key.ExportSubjectPublicKeyInfo();
    }

    public static CheckpointSigner FromPem(string pemPath)
    {
        var pem = File.ReadAllText(pemPath);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return new CheckpointSigner(ecdsa);
    }

    public static CheckpointSigner Generate()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CheckpointSigner(ecdsa);
    }

    public byte[] PublicKeySpki => _publicKeySpki;

    public string PublicKeyBase64 => Convert.ToBase64String(_publicKeySpki);

    /// <summary>
    /// Signs a checkpoint payload (JCS-canonicalized JSON) and returns
    /// a base64-encoded string of the form: "json_payload.base64_signature".
    /// </summary>
    public string SignCheckpoint(long treeSize, string rootHash, string timestamp)
    {
        var payload = JsonSerializer.Serialize(new
        {
            treeSize,
            rootHash,
            timestamp
        });

        var canonical = new JsonCanonicalizer(payload).GetEncodedUTF8();
        var signature = _key.SignData(canonical, HashAlgorithmName.SHA256);

        var combined = Encoding.UTF8.GetString(canonical) + "." + Convert.ToBase64String(signature);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(combined));
    }

    public void Dispose()
    {
        _key.Dispose();
    }
}
