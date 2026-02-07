using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustSignCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle to sign" };
        var keyOption = new Option<string>("--key") { Description = "Path to the authority's private key PEM" };
        keyOption.Required = true;
        var outputOption = new Option<string?>("-o") { Description = "Output path for signed bundle" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the key is encrypted" };

        var cmd = new Command("sign", "Sign a trust bundle with an authority key");
        cmd.Add(bundleArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(passphraseOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var keyPath = parseResult.GetValue(keyOption)!;
            var output = parseResult.GetValue(outputOption);
            var passphrase = parseResult.GetValue(passphraseOption);

            if (!bundleFile.Exists)
            {
                Console.Error.WriteLine($"Bundle not found: {bundleFile.FullName}");
                return;
            }

            if (!File.Exists(keyPath))
            {
                Console.Error.WriteLine($"Key file not found: {keyPath}");
                return;
            }

            char[]? passphraseChars = passphrase?.ToCharArray();

            try
            {
                // Load PEM with secure memory handling
                byte[] pemBytes = File.ReadAllBytes(keyPath);
                char[] pemChars = Encoding.UTF8.GetChars(pemBytes);
                ISigner signer;

                try
                {
                    bool isEncrypted = pemChars.AsSpan().IndexOf("ENCRYPTED".AsSpan()) >= 0;
                    if (isEncrypted)
                    {
                        if (passphraseChars is null || passphraseChars.Length == 0)
                        {
                            Console.Error.WriteLine("Key is encrypted. Provide --passphrase.");
                            return;
                        }
                        signer = SignerFactory.CreateFromPem(pemChars, passphraseChars);
                    }
                    else
                    {
                        signer = SignerFactory.CreateFromPem(pemChars);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pemBytes);
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pemChars.AsSpan()));
                }

                using (signer)
                {
                    var json = File.ReadAllText(bundleFile.FullName);
                    var deserializeResult = BundleSigner.Deserialize(json);
                    if (!deserializeResult.IsSuccess)
                    {
                        Console.Error.WriteLine($"Failed to parse bundle: {deserializeResult.ErrorMessage}");
                        return;
                    }

                    var bundle = deserializeResult.Value;
                    var signResult = BundleSigner.Sign(bundle, signer);
                    if (!signResult.IsSuccess)
                    {
                        Console.Error.WriteLine($"Failed to sign bundle: {signResult.ErrorMessage}");
                        return;
                    }

                    var outputPath = output ?? bundleFile.FullName;
                    var serializeResult = BundleSigner.Serialize(signResult.Value);
                    if (!serializeResult.IsSuccess)
                    {
                        Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                        return;
                    }

                    File.WriteAllText(outputPath, serializeResult.Value);
                    Console.WriteLine($"Signed bundle: {outputPath}");
                    Console.WriteLine($"Authority: {signResult.Value.Signature!.KeyId}");
                }
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
