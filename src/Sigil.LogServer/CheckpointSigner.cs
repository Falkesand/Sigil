using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;

namespace Sigil.LogServer;

public sealed class CheckpointSigner : ICheckpointSigner
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
        byte[] pemBytes = File.ReadAllBytes(pemPath);
        char[] pemChars = Encoding.UTF8.GetChars(pemBytes);
        try
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pemChars);
            return new CheckpointSigner(ecdsa);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pemBytes);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pemChars.AsSpan()));
        }
    }

    public static CheckpointSigner FromPfx(string pfxPath, string? password = null)
    {
        var pfxBytes = File.ReadAllBytes(pfxPath);
        try
        {
            var cert = X509CertificateLoader.LoadPkcs12(
                pfxBytes, password,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
            try
            {
                var ecKey = cert.GetECDsaPrivateKey()
                    ?? throw new ArgumentException("PFX does not contain an ECDSA private key.");
                // Clone the key so cert disposal doesn't invalidate it
                var ecdsa = ECDsa.Create();
                var pkcs8 = ecKey.ExportPkcs8PrivateKey();
                try
                {
                    ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pkcs8);
                }
                return new CheckpointSigner(ecdsa);
            }
            finally
            {
                cert.Dispose();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfxBytes);
        }
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
