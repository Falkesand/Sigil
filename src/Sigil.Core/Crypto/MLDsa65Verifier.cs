#pragma warning disable SYSLIB5006

using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Verifies ML-DSA-65 (FIPS 204) signatures.
/// Post-quantum lattice-based signature verification — NIST security category 3.
/// </summary>
public sealed class MLDsa65Verifier : IVerifier
{
    private static readonly byte[] EmptyContext = [];

    private readonly MLDsa _key;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.MLDsa65;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.ExportSubjectPublicKeyInfo();
        }
    }

    private MLDsa65Verifier(MLDsa key)
    {
        _key = key;
    }

    public static MLDsa65Verifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException("ML-DSA is not supported on this platform.");
        return new MLDsa65Verifier(MLDsa.ImportSubjectPublicKeyInfo(spki));
    }

    public static MLDsa65Verifier FromPublicKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException("ML-DSA is not supported on this platform.");
        return new MLDsa65Verifier(MLDsa.ImportFromPem(pem));
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        return _key.VerifyData(data, signature, EmptyContext);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _key.Dispose();
            _disposed = true;
        }
    }
}
