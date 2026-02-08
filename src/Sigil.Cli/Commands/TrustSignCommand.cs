using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustSignCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle to sign" };
        var keyOption = new Option<string?>("--key") { Description = "Path to the authority's private key PEM" };
        var outputOption = new Option<string?>("-o") { Description = "Output path for signed bundle" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the key is encrypted" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };

        var cmd = new Command("sign", "Sign a trust bundle with an authority key");
        cmd.Add(bundleArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(passphraseOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);

        cmd.SetAction(async parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);

            if (!bundleFile.Exists)
            {
                Console.Error.WriteLine($"Bundle not found: {bundleFile.FullName}");
                return;
            }

            // Validate: must have either --key or --vault, not both, not neither
            if (vaultName is not null && keyPath is not null)
            {
                Console.Error.WriteLine("Cannot use both --key and --vault. Choose one signing method.");
                return;
            }

            if (vaultName is null && keyPath is null)
            {
                Console.Error.WriteLine("Either --key or --vault is required.");
                return;
            }

            if (vaultName is not null && vaultKey is null)
            {
                Console.Error.WriteLine("--vault-key is required when using --vault.");
                return;
            }

            if (vaultKey is not null && vaultName is null)
            {
                Console.Error.WriteLine("--vault is required when using --vault-key.");
                return;
            }

            // Read and parse bundle
            var json = File.ReadAllText(bundleFile.FullName);
            var deserializeResult = BundleSigner.Deserialize(json);
            if (!deserializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to parse bundle: {deserializeResult.ErrorMessage}");
                return;
            }

            var bundle = deserializeResult.Value;

            // Vault signing path
            if (vaultName is not null)
            {
                var providerResult = VaultProviderFactory.Create(vaultName);
                if (!providerResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Vault error: {providerResult.ErrorMessage}");
                    return;
                }

                await using var provider = providerResult.Value;
                var signerResult = await provider.GetSignerAsync(vaultKey!);
                if (!signerResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Vault error: {signerResult.ErrorMessage}");
                    return;
                }

                using var signer = signerResult.Value;
                var signResult = await BundleSigner.SignAsync(bundle, signer);
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
                Console.WriteLine($"Mode: vault ({vaultName})");
                return;
            }

            // Local PEM signing path
            if (!File.Exists(keyPath))
            {
                Console.Error.WriteLine($"Key file not found: {keyPath}");
                return;
            }

            char[]? passphraseChars = passphrase?.ToCharArray();

            try
            {
                byte[] pemBytes = File.ReadAllBytes(keyPath!);
                char[] pemChars = Encoding.UTF8.GetChars(pemBytes);
                ISigner localSigner;

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
                        localSigner = SignerFactory.CreateFromPem(pemChars, passphraseChars);
                    }
                    else
                    {
                        localSigner = SignerFactory.CreateFromPem(pemChars);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pemBytes);
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pemChars.AsSpan()));
                }

                using (localSigner)
                {
                    var signResult = BundleSigner.Sign(bundle, localSigner);
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
