using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;

namespace Sigil.Cli.Commands;

/// <summary>
/// Loads a signer from a PEM file with secure memory handling.
/// Centralizes PEM reading, passphrase validation, algorithm hint parsing,
/// and memory zeroing that was duplicated across sign commands.
/// </summary>
public static class PemSignerLoader
{
    public static PemLoadResult<ISigner> Load(string keyPath, string? passphrase, string? algorithmName)
    {
        if (!File.Exists(keyPath))
            return PemLoadResult<ISigner>.Fail(
                PemLoadErrorKind.FileNotFound, $"Key file not found: {keyPath}");

        SigningAlgorithm? algorithmHint = null;
        if (algorithmName is not null)
        {
            try
            {
                algorithmHint = SigningAlgorithmExtensions.ParseAlgorithm(algorithmName);
            }
            catch (ArgumentException)
            {
                return PemLoadResult<ISigner>.Fail(
                    PemLoadErrorKind.UnknownAlgorithm,
                    $"Unknown algorithm: {algorithmName}\nSupported: ecdsa-p256, ecdsa-p384, rsa-pss-sha256, ml-dsa-65");
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
                    return PemLoadResult<ISigner>.Fail(
                        PemLoadErrorKind.PassphraseRequired,
                        "Key is encrypted. Provide --passphrase.");

                var signer = SignerFactory.CreateFromPem(pemChars, passphraseChars, algorithmHint);
                return PemLoadResult<ISigner>.Ok(signer);
            }

            return PemLoadResult<ISigner>.Ok(SignerFactory.CreateFromPem(pemChars));
        }
        catch (CryptographicException ex)
        {
            return PemLoadResult<ISigner>.Fail(
                PemLoadErrorKind.CryptoError, $"Failed to load key: {ex.Message}");
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
