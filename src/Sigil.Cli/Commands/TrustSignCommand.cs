using System.CommandLine;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keys;
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
        var passphraseFileOption = new Option<string?>("--passphrase-file") { Description = "Path to file containing the passphrase" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Algorithm hint for encrypted PEM detection (ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-pss-sha256, ml-dsa-65)" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };
        var certStoreOption = new Option<string?>("--cert-store") { Description = "Certificate thumbprint for Windows Certificate Store" };
        var storeLocationOption = new Option<string?>("--store-location") { Description = "Store location: CurrentUser (default) or LocalMachine" };

        var cmd = new Command("sign", "Sign a trust bundle with an authority key");
        cmd.Add(bundleArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(passphraseOption);
        cmd.Add(passphraseFileOption);
        cmd.Add(algorithmOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);
        cmd.Add(certStoreOption);
        cmd.Add(storeLocationOption);

        cmd.SetAction(async parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var passphraseFile = parseResult.GetValue(passphraseFileOption);
            var algorithmName = parseResult.GetValue(algorithmOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);
            var certStoreThumbprint = parseResult.GetValue(certStoreOption);
            var storeLocationName = parseResult.GetValue(storeLocationOption);

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

            if (vaultName is null && keyPath is null && certStoreThumbprint is null)
            {
                Console.Error.WriteLine("Either --key, --vault, or --cert-store is required.");
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

            if (certStoreThumbprint is not null && keyPath is not null)
            {
                Console.Error.WriteLine("Cannot use both --key and --cert-store. Choose one signing method.");
                return;
            }

            if (certStoreThumbprint is not null && vaultName is not null)
            {
                Console.Error.WriteLine("Cannot use both --vault and --cert-store. Choose one signing method.");
                return;
            }

            if (storeLocationName is not null && certStoreThumbprint is null)
            {
                Console.Error.WriteLine("--store-location requires --cert-store.");
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

                if (string.Equals(vaultName, "pkcs11", StringComparison.OrdinalIgnoreCase))
                    Console.Error.WriteLine("Waiting for PKCS#11 device (touch may be required)...");

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

            // Certificate store signing path (Windows only)
            if (certStoreThumbprint is not null)
            {
                if (!OperatingSystem.IsWindows())
                {
                    Console.Error.WriteLine("--cert-store is only supported on Windows.");
                    return;
                }
                var storeLocation = storeLocationName is not null
                    ? Enum.Parse<System.Security.Cryptography.X509Certificates.StoreLocation>(storeLocationName, ignoreCase: true)
                    : System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser;
                await using var certProvider = new CertStoreKeyProvider(storeLocation);
                var signerResult = await certProvider.GetSignerAsync(certStoreThumbprint);
                if (!signerResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Certificate store error: {signerResult.ErrorMessage}");
                    return;
                }

                using var certSigner = signerResult.Value;

                var signResult = await BundleSigner.SignAsync(bundle, certSigner);
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
                Console.WriteLine($"Mode: cert-store");
                return;
            }

            // Local PEM signing path
            var resolvedPassphrase = PassphraseResolver.Resolve(passphrase, passphraseFile);
            var loadResult = KeyLoader.Load(keyPath!, resolvedPassphrase, algorithmName);
            if (!loadResult.IsSuccess)
            {
                Console.Error.WriteLine(loadResult.ErrorMessage);
                return;
            }

            using (var localSigner = loadResult.Value)
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
        });

        return cmd;
    }
}
