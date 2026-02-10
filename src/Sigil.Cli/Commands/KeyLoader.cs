using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Cli.Commands;

/// <summary>
/// Loads a signer from a key file (PEM or PFX) with secure memory handling.
/// Auto-detects PFX by file extension (.pfx, .p12).
/// </summary>
public static class KeyLoader
{
    private static readonly string[] PfxExtensions = [".pfx", ".p12"];

    public static KeyLoadResult<ISigner> Load(string keyPath, string? passphrase, string? algorithmName)
    {
        if (!File.Exists(keyPath))
            return KeyLoadResult<ISigner>.Fail(
                KeyLoadErrorKind.FileNotFound, $"Key file not found: {keyPath}");

        // Auto-detect PFX by extension
        var extension = Path.GetExtension(keyPath);
        if (PfxExtensions.Any(ext => string.Equals(ext, extension, StringComparison.OrdinalIgnoreCase)))
            return LoadPfx(keyPath, passphrase);

        return LoadPem(keyPath, passphrase, algorithmName);
    }

    private static KeyLoadResult<ISigner> LoadPfx(string keyPath, string? passphrase)
    {
        var pfxResult = PfxLoader.Load(keyPath, passphrase);
        if (!pfxResult.IsSuccess)
        {
            var errorKind = pfxResult.ErrorKind switch
            {
                PfxLoadErrorKind.FileNotFound => KeyLoadErrorKind.FileNotFound,
                PfxLoadErrorKind.PasswordRequired => KeyLoadErrorKind.PassphraseRequired,
                PfxLoadErrorKind.InvalidFormat => KeyLoadErrorKind.CryptoError,
                PfxLoadErrorKind.NoPrivateKey => KeyLoadErrorKind.CryptoError,
                PfxLoadErrorKind.NonExportableKey => KeyLoadErrorKind.CryptoError,
                PfxLoadErrorKind.UnsupportedAlgorithm => KeyLoadErrorKind.UnsupportedFormat,
                _ => KeyLoadErrorKind.CryptoError
            };
            return KeyLoadResult<ISigner>.Fail(errorKind, pfxResult.ErrorMessage);
        }

        return KeyLoadResult<ISigner>.Ok(pfxResult.Value);
    }

    private static KeyLoadResult<ISigner> LoadPem(string keyPath, string? passphrase, string? algorithmName)
    {
        SigningAlgorithm? algorithmHint = null;
        if (algorithmName is not null)
        {
            try
            {
                algorithmHint = SigningAlgorithmExtensions.ParseAlgorithm(algorithmName);
            }
            catch (ArgumentException)
            {
                return KeyLoadResult<ISigner>.Fail(
                    KeyLoadErrorKind.UnknownAlgorithm,
                    $"Unknown algorithm: {algorithmName}\nSupported: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-pss-sha256, ml-dsa-65");
            }
        }

        char[]? passphraseChars = passphrase?.ToCharArray();
        byte[] pemBytes = File.ReadAllBytes(keyPath);
        char[] pemChars = Encoding.UTF8.GetChars(pemBytes);

        try
        {
            bool isEncrypted = pemChars.AsSpan().IndexOf("ENCRYPTED".AsSpan()) >= 0;

            if (isEncrypted)
            {
                if (passphraseChars is null || passphraseChars.Length == 0)
                    return KeyLoadResult<ISigner>.Fail(
                        KeyLoadErrorKind.PassphraseRequired,
                        "Key is encrypted. Provide --passphrase.");

                var signer = SignerFactory.CreateFromPem(pemChars, passphraseChars, algorithmHint);
                return KeyLoadResult<ISigner>.Ok(signer);
            }

            return KeyLoadResult<ISigner>.Ok(SignerFactory.CreateFromPem(pemChars));
        }
        catch (CryptographicException ex)
        {
            return KeyLoadResult<ISigner>.Fail(
                KeyLoadErrorKind.CryptoError, $"Failed to load key: {ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pemBytes);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pemChars.AsSpan()));
            if (passphraseChars is not null)
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passphraseChars.AsSpan()));
        }
    }
}
