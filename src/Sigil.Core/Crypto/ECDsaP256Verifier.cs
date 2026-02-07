using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Verifies ECDSA P-256 signatures. BCL-only, no external dependencies.
/// </summary>
public sealed class ECDsaP256Verifier : IVerifier
{
    private readonly ECDsa _key;

    public SigningAlgorithm Algorithm => SigningAlgorithm.ECDsaP256;

    public byte[] PublicKey => _key.ExportSubjectPublicKeyInfo();

    private ECDsaP256Verifier(ECDsa key)
    {
        _key = key;
    }

    public static ECDsaP256Verifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return new ECDsaP256Verifier(key);
    }

    public static ECDsaP256Verifier FromPublicKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return new ECDsaP256Verifier(key);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        return _key.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }
}
