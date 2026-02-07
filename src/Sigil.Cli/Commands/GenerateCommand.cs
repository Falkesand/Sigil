using System.CommandLine;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Cli.Commands;

public static class GenerateCommand
{
    public static Command Create()
    {
        var outputOption = new Option<string?>("-o") { Description = "Output file prefix (writes <prefix>.pem and <prefix>.pub.pem)" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase to encrypt the private key" };

        var cmd = new Command("generate", "Generate a new signing key pair");
        cmd.Add(outputOption);
        cmd.Add(passphraseOption);

        cmd.SetAction(parseResult =>
        {
            var outputPrefix = parseResult.GetValue(outputOption);
            var passphrase = parseResult.GetValue(passphraseOption);

            using var signer = ECDsaP256Signer.Generate();
            var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

            if (outputPrefix is not null)
            {
                var privatePath = outputPrefix + ".pem";
                var publicPath = outputPrefix + ".pub.pem";

                var privatePem = string.IsNullOrEmpty(passphrase)
                    ? signer.ExportPrivateKeyPem()
                    : signer.ExportEncryptedPrivateKeyPem(passphrase);

                File.WriteAllText(privatePath, privatePem);
                File.WriteAllText(publicPath, signer.ExportPublicKeyPem());

                Console.WriteLine($"Private key: {privatePath}");
                Console.WriteLine($"Public key:  {publicPath}");
                if (passphrase is not null)
                    Console.WriteLine("Private key encrypted with passphrase.");
            }
            else
            {
                // Print private key PEM to stdout
                var privatePem = string.IsNullOrEmpty(passphrase)
                    ? signer.ExportPrivateKeyPem()
                    : signer.ExportEncryptedPrivateKeyPem(passphrase);

                Console.WriteLine(privatePem);
            }

            Console.Error.WriteLine($"Fingerprint: {fingerprint.Value}");
        });

        return cmd;
    }
}
