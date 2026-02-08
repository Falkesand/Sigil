using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Cli.Commands;

public static class GenerateCommand
{
    public static Command Create()
    {
        var outputOption = new Option<string?>("-o") { Description = "Output file prefix (writes <prefix>.pem and <prefix>.pub.pem)" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase to encrypt the private key" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm (ecdsa-p256, ecdsa-p384, rsa-pss-sha256, ml-dsa-65)" };

        var cmd = new Command("generate", "Generate a new signing key pair");
        cmd.Add(outputOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);

        cmd.SetAction(parseResult =>
        {
            var outputPrefix = parseResult.GetValue(outputOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption) ?? "ecdsa-p256";

            SigningAlgorithm algorithm;
            try
            {
                algorithm = SigningAlgorithmExtensions.ParseAlgorithm(algorithmName);
            }
            catch (ArgumentException)
            {
                Console.Error.WriteLine($"Unknown algorithm: {algorithmName}");
                Console.Error.WriteLine("Supported: ecdsa-p256, ecdsa-p384, rsa-pss-sha256, ml-dsa-65");
                return;
            }

            // Convert passphrase to char[] so we can zero it after use
            char[]? passphraseChars = passphrase?.ToCharArray();

            try
            {
                using var signer = SignerFactory.Generate(algorithm);
                var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

                if (outputPrefix is not null)
                {
                    var privatePath = outputPrefix + ".pem";
                    var publicPath = outputPrefix + ".pub.pem";

                    // Export as byte[] so we can zero after writing
                    byte[] privatePemBytes = string.IsNullOrEmpty(passphrase)
                        ? signer.ExportPrivateKeyPemBytes()
                        : signer.ExportEncryptedPrivateKeyPemBytes(passphraseChars);
                    try
                    {
                        File.WriteAllBytes(privatePath, privatePemBytes);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(privatePemBytes);
                    }

                    File.WriteAllText(publicPath, signer.ExportPublicKeyPem());

                    Console.WriteLine($"Algorithm: {algorithm.ToCanonicalName()}");
                    Console.WriteLine($"Private key: {privatePath}");
                    Console.WriteLine($"Public key:  {publicPath}");
                    if (passphrase is not null)
                        Console.WriteLine("Private key encrypted with passphrase.");
                }
                else
                {
                    // Print private key PEM to stdout — byte source is zeroed
                    byte[] privatePemBytes = string.IsNullOrEmpty(passphrase)
                        ? signer.ExportPrivateKeyPemBytes()
                        : signer.ExportEncryptedPrivateKeyPemBytes(passphraseChars);
                    try
                    {
                        Console.Out.Write(Encoding.UTF8.GetString(privatePemBytes));
                        Console.WriteLine();
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(privatePemBytes);
                    }
                }

                Console.Error.WriteLine($"Fingerprint: {fingerprint.Value}");
            }
            finally
            {
                if (passphraseChars is not null)
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passphraseChars.AsSpan()));
            }
        });

        return cmd;
    }
}
