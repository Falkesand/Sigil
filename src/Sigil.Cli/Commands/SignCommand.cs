using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Cli.Commands;

public static class SignCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to sign" };
        var keyOption = new Option<string?>("--key") { Description = "Path to a private key PEM file (ephemeral if omitted)" };
        var outputOption = new Option<string?>("--output") { Description = "Output path for the signature file" };
        var labelOption = new Option<string?>("--label") { Description = "Label for this signature" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm for ephemeral mode (ecdsa-p256, ecdsa-p384, rsa-pss-sha256, ml-dsa-65)" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };

        var cmd = new Command("sign", "Sign an artifact and produce a detached signature envelope");
        cmd.Add(artifactArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption) ?? "ecdsa-p256";
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

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
                var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
                var envelope = await ArtifactSigner.SignAsync(artifact.FullName, signer, fingerprint, label);

                var outputPath = output ?? artifact.FullName + ".sig.json";
                var json = ArtifactSigner.Serialize(envelope);
                File.WriteAllText(outputPath, json);

                Console.WriteLine($"Signed: {artifact.Name}");
                Console.WriteLine($"Algorithm: {signer.Algorithm.ToCanonicalName()}");
                Console.WriteLine($"Key: {fingerprint.ShortId}...");
                Console.WriteLine($"Mode: vault ({vaultName})");
                if (envelope.Subject.Metadata?.TryGetValue("sbom.format", out var sbomFormat) == true)
                    Console.WriteLine($"Format: {sbomFormat} ({envelope.Subject.MediaType})");
                Console.WriteLine($"Signature: {outputPath}");
                return;
            }

            // Local signing paths (PEM or ephemeral)
            ISigner localSigner;
            bool isEphemeral;

            char[]? passphraseChars = passphrase?.ToCharArray();

            try
            {
                if (keyPath is not null)
                {
                    // Persistent mode: load from PEM file with auto-detection
                    if (!File.Exists(keyPath))
                    {
                        Console.Error.WriteLine($"Key file not found: {keyPath}");
                        return;
                    }

                    byte[] pemBytes = File.ReadAllBytes(keyPath);
                    char[] pemChars = Encoding.UTF8.GetChars(pemBytes);
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

                    isEphemeral = false;
                }
                else
                {
                    // Ephemeral mode: generate key in memory
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

                    localSigner = SignerFactory.Generate(algorithm);
                    isEphemeral = true;
                }

                using (localSigner)
                {
                    var fingerprint = KeyFingerprint.Compute(localSigner.PublicKey);
                    var envelope = ArtifactSigner.Sign(artifact.FullName, localSigner, fingerprint, label);

                    var outputPath = output ?? artifact.FullName + ".sig.json";
                    var json = ArtifactSigner.Serialize(envelope);
                    File.WriteAllText(outputPath, json);

                    Console.WriteLine($"Signed: {artifact.Name}");
                    Console.WriteLine($"Algorithm: {localSigner.Algorithm.ToCanonicalName()}");
                    Console.WriteLine($"Key: {fingerprint.ShortId}...");
                    if (isEphemeral)
                        Console.WriteLine("Mode: ephemeral (key not persisted)");
                    if (envelope.Subject.Metadata?.TryGetValue("sbom.format", out var sbomFormat) == true)
                        Console.WriteLine($"Format: {sbomFormat} ({envelope.Subject.MediaType})");
                    Console.WriteLine($"Signature: {outputPath}");
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
