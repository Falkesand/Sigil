using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

using BcPemObject = Org.BouncyCastle.Utilities.IO.Pem.PemObject;

namespace Sigil.Crypto.BouncyCastle;

/// <summary>
/// Ed25519 signer backed by BouncyCastle. Implements <see cref="ISigner"/> for use with
/// Sigil's factory pattern. The class name avoids collision with BouncyCastle's own Ed25519Signer.
/// </summary>
public sealed class Ed25519BouncyCastleSigner : ISigner
{
    private readonly Ed25519PrivateKeyParameters _privateKey;
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

    private Ed25519BouncyCastleSigner(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    /// <summary>
    /// Generates a new Ed25519 key pair and returns a signer.
    /// </summary>
    public static Ed25519BouncyCastleSigner Generate()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        return new Ed25519BouncyCastleSigner(
            (Ed25519PrivateKeyParameters)keyPair.Private,
            (Ed25519PublicKeyParameters)keyPair.Public);
    }

    /// <summary>
    /// Creates a signer from DER-encoded PKCS#8 private key bytes.
    /// </summary>
    public static Ed25519BouncyCastleSigner FromPkcs8(byte[] pkcs8Der)
    {
        ArgumentNullException.ThrowIfNull(pkcs8Der);
        var privateKey = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(pkcs8Der);
        var publicKey = privateKey.GeneratePublicKey();
        return new Ed25519BouncyCastleSigner(privateKey, publicKey);
    }

    /// <summary>
    /// Creates a signer from a PEM-encoded private key, optionally encrypted with a passphrase.
    /// </summary>
    public static Ed25519BouncyCastleSigner FromPem(ReadOnlyMemory<char> pem, ReadOnlyMemory<char> passphrase)
    {
        var pemString = pem.ToString();
        using var reader = new StringReader(pemString);

        object pemObject;
        if (!passphrase.IsEmpty)
        {
            var passwordChars = passphrase.ToString().ToCharArray();
            try
            {
                var pemReader = new PemReader(reader, new PasswordFinderAdapter(passwordChars));
                pemObject = pemReader.ReadObject() ?? throw new FormatException("Failed to read PEM object.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passwordChars.AsSpan()));
            }
        }
        else
        {
            var pemReader = new PemReader(reader);
            pemObject = pemReader.ReadObject() ?? throw new FormatException("Failed to read PEM object.");
        }

        Ed25519PrivateKeyParameters privateKey;
        Ed25519PublicKeyParameters publicKey;

        if (pemObject is AsymmetricCipherKeyPair keyPair)
        {
            privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;
            publicKey = (Ed25519PublicKeyParameters)keyPair.Public;
        }
        else if (pemObject is Ed25519PrivateKeyParameters privKey)
        {
            privateKey = privKey;
            publicKey = privKey.GeneratePublicKey();
        }
        else
        {
            throw new FormatException($"Unexpected PEM object type: {pemObject.GetType().Name}");
        }

        return new Ed25519BouncyCastleSigner(privateKey, publicKey);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);

        var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public string ExportPublicKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var writer = new StringWriter();
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(_publicKey);
        return writer.ToString();
    }

    public byte[] ExportPrivateKeyPemBytes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var writer = new StringWriter();
        var pemWriter = new PemWriter(writer);
        var pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_privateKey);
        pemWriter.WriteObject(pkcs8);
        return Encoding.UTF8.GetBytes(writer.ToString());
    }

    public byte[] ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char> password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        var passwordChars = password.ToString().ToCharArray();
        try
        {
            var random = new SecureRandom();
            var salt = new byte[16];
            random.NextBytes(salt);

            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_privateKey);
            var encryptedInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                NistObjectIdentifiers.IdAes256Cbc,
                PkcsObjectIdentifiers.IdHmacWithSha256,
                passwordChars,
                salt,
                100_000,
                random,
                keyInfo);

            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(new BcPemObject("ENCRYPTED PRIVATE KEY", encryptedInfo.GetEncoded()));
            return Encoding.UTF8.GetBytes(writer.ToString());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passwordChars.AsSpan()));
        }
    }

    public ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
        => new(Sign(data));

    public bool CanExportPrivateKey => true;

    /// <summary>
    /// Disposes the signer. Note: BouncyCastle's <see cref="Ed25519PrivateKeyParameters"/>
    /// does not support explicit zeroing of key material in memory. The private key bytes
    /// remain in managed memory until garbage collected. This is a known limitation of the
    /// BouncyCastle library.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
    }
}
