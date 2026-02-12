using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Sigil.Crypto.BouncyCastle;

/// <summary>
/// Ed25519 verifier backed by BouncyCastle. Implements <see cref="IVerifier"/> for use with
/// Sigil's factory pattern.
/// </summary>
public sealed class Ed25519BouncyCastleVerifier : IVerifier
{
    private readonly Ed25519PublicKeyParameters _publicKey;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.Ed25519;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var spkiInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKey);
            return spkiInfo.GetDerEncoded();
        }
    }

    private Ed25519BouncyCastleVerifier(Ed25519PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
    }

    /// <summary>
    /// Creates a verifier from DER-encoded SPKI public key bytes.
    /// </summary>
    public static Ed25519BouncyCastleVerifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var publicKey = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(spki);
        return new Ed25519BouncyCastleVerifier(publicKey);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        var verifier = new Ed25519Signer();
        verifier.Init(false, _publicKey);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
    }
}
