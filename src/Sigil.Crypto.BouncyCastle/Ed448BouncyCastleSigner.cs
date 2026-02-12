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
/// Ed448 signer backed by BouncyCastle. Implements <see cref="ISigner"/> for use with
/// Sigil's factory pattern. The class name avoids collision with BouncyCastle's own Ed448Signer.
/// </summary>
public sealed class Ed448BouncyCastleSigner : ISigner
{
    private readonly Ed448PrivateKeyParameters _privateKey;
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

    private Ed448BouncyCastleSigner(Ed448PrivateKeyParameters privateKey, Ed448PublicKeyParameters publicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    /// <summary>
    /// Generates a new Ed448 key pair and returns a signer.
    /// </summary>
    public static Ed448BouncyCastleSigner Generate()
    {
        var generator = new Ed448KeyPairGenerator();
        generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        return new Ed448BouncyCastleSigner(
            (Ed448PrivateKeyParameters)keyPair.Private,
            (Ed448PublicKeyParameters)keyPair.Public);
    }

    /// <summary>
    /// Creates a signer from DER-encoded PKCS#8 private key bytes.
    /// </summary>
    public static Ed448BouncyCastleSigner FromPkcs8(byte[] pkcs8Der)
    {
        ArgumentNullException.ThrowIfNull(pkcs8Der);
        var privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(pkcs8Der);
        var publicKey = privateKey.GeneratePublicKey();
        return new Ed448BouncyCastleSigner(privateKey, publicKey);
    }

    /// <summary>
    /// Creates a signer from a PEM-encoded private key, optionally encrypted with a passphrase.
    /// </summary>
    public static Ed448BouncyCastleSigner FromPem(ReadOnlyMemory<char> pem, ReadOnlyMemory<char> passphrase)
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

        Ed448PrivateKeyParameters privateKey;
        Ed448PublicKeyParameters publicKey;

        if (pemObject is AsymmetricCipherKeyPair keyPair)
        {
            privateKey = (Ed448PrivateKeyParameters)keyPair.Private;
            publicKey = (Ed448PublicKeyParameters)keyPair.Public;
        }
        else if (pemObject is Ed448PrivateKeyParameters privKey)
        {
            privateKey = privKey;
            publicKey = privKey.GeneratePublicKey();
        }
        else
        {
            throw new FormatException($"Unexpected PEM object type: {pemObject.GetType().Name}");
        }

        return new Ed448BouncyCastleSigner(privateKey, publicKey);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);

        var signer = new Org.BouncyCastle.Crypto.Signers.Ed448Signer(Array.Empty<byte>());
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
    /// Disposes the signer. Note: BouncyCastle's <see cref="Ed448PrivateKeyParameters"/>
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
