using System.CommandLine;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Oci;

namespace Sigil.Cli.Commands;

public static class SignImageCommand
{
    public static Command Create()
    {
        var imageArg = new Argument<string>("image") { Description = "Image reference (e.g., registry/repo:tag)" };
        var keyOption = new Option<string?>("--key") { Description = "Path to a private key PEM file (ephemeral if omitted)" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm (ephemeral default: ecdsa-p256)" };
        var labelOption = new Option<string?>("--label") { Description = "Label for this signature" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp, pkcs11" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };
        var timestampOption = new Option<string?>("--timestamp") { Description = "TSA URL for RFC 3161 timestamping" };

        var cmd = new Command("sign-image", "Sign an OCI container image");
        cmd.Add(imageArg);
        cmd.Add(keyOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);
        cmd.Add(labelOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);
        cmd.Add(timestampOption);

        cmd.SetAction(async parseResult =>
        {
            var image = parseResult.GetValue(imageArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption);
            var label = parseResult.GetValue(labelOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);
            var tsaUrl = parseResult.GetValue(timestampOption);

            // Validate mutual exclusivity
            if (vaultName is not null && keyPath is not null)
            {
                Console.Error.WriteLine("Cannot use both --key and --vault. Choose one signing method.");
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

            // Parse image reference
            var refResult = ImageReference.Parse(image);
            if (!refResult.IsSuccess)
            {
                Console.Error.WriteLine($"Invalid image reference: {refResult.ErrorMessage}");
                return;
            }

            var imageRef = refResult.Value;

            // Resolve credentials
            var creds = RegistryCredentialResolver.Resolve(imageRef.Registry);

            // Resolve signer
            ISigner signer;
            bool isEphemeral;
            string signingMode;

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

                signer = signerResult.Value;
                isEphemeral = false;
                signingMode = $"vault ({vaultName})";

                if (string.Equals(vaultName, "pkcs11", StringComparison.OrdinalIgnoreCase))
                    Console.Error.WriteLine("Waiting for PKCS#11 device (touch may be required)...");

                try
                {
                    await SignAndPushAsync(imageRef, signer, creds, label, tsaUrl, signingMode, isEphemeral);
                }
                finally
                {
                    signer.Dispose();
                }
                return;
            }

            if (keyPath is not null)
            {
                var loadResult = PemSignerLoader.Load(keyPath, passphrase, algorithmName);
                if (!loadResult.IsSuccess)
                {
                    Console.Error.WriteLine(loadResult.ErrorMessage);
                    return;
                }

                signer = loadResult.Value;
                isEphemeral = false;
                signingMode = "persistent key";
            }
            else
            {
                var ephemeralAlgorithmName = algorithmName ?? "ecdsa-p256";
                SigningAlgorithm algorithm;
                try
                {
                    algorithm = SigningAlgorithmExtensions.ParseAlgorithm(ephemeralAlgorithmName);
                }
                catch (ArgumentException)
                {
                    Console.Error.WriteLine($"Unknown algorithm: {ephemeralAlgorithmName}");
                    Console.Error.WriteLine("Supported: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-pss-sha256, ml-dsa-65");
                    return;
                }

                signer = SignerFactory.Generate(algorithm);
                isEphemeral = true;
                signingMode = "ephemeral (key not persisted)";
            }

            using (signer)
            {
                await SignAndPushAsync(imageRef, signer, creds, label, tsaUrl, signingMode, isEphemeral);
            }
        });

        return cmd;
    }

    private static async Task SignAndPushAsync(
        ImageReference imageRef, ISigner signer, RegistryCredentials creds,
        string? label, string? tsaUrl, string signingMode, bool isEphemeral)
    {
        Uri? tsaUri = null;
        if (tsaUrl is not null)
        {
            if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out tsaUri))
            {
                Console.Error.WriteLine($"Invalid TSA URL: {tsaUrl}");
                return;
            }
        }

        using var registryClient = new OciRegistryClient(imageRef, creds);
        var result = await OciImageSigner.SignAsync(registryClient, imageRef, signer, label, tsaUri);

        if (!result.IsSuccess)
        {
            Console.Error.WriteLine($"Signing failed: {result.ErrorMessage}");
            return;
        }

        Console.WriteLine($"Signed: {imageRef.FullName}");
        Console.WriteLine($"Digest: {result.Value.ManifestDigest}");
        Console.WriteLine($"Algorithm: {result.Value.Algorithm}");
        Console.WriteLine($"Key: {result.Value.KeyId[..12]}...");
        Console.WriteLine($"Mode: {signingMode}");
        Console.WriteLine($"Signature: {result.Value.SignatureDigest}");
    }
}
