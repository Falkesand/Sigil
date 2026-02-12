using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Sigil.Crypto.BouncyCastle;

/// <summary>
/// Ed448 verifier backed by BouncyCastle. Implements <see cref="IVerifier"/> for use with
/// Sigil's factory pattern.
/// </summary>
public sealed class Ed448BouncyCastleVerifier : IVerifier
{
    private readonly Ed448PublicKeyParameters _publicKey;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.Ed448;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var spkiInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKey);
            return spkiInfo.GetDerEncoded();
        }
    }

    private Ed448BouncyCastleVerifier(Ed448PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
    }

    /// <summary>
    /// Creates a verifier from DER-encoded SPKI public key bytes.
    /// </summary>
    public static Ed448BouncyCastleVerifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var publicKey = (Ed448PublicKeyParameters)PublicKeyFactory.CreateKey(spki);
        return new Ed448BouncyCastleVerifier(publicKey);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        var verifier = new Ed448Signer(Array.Empty<byte>());
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
