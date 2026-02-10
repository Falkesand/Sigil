using System.CommandLine;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Cli.Commands;

public static class SignManifestCommand
{
    public static Command Create()
    {
        var pathArg = new Argument<string>("path") { Description = "Directory or glob pattern for files to sign" };
        var keyOption = new Option<string?>("--key") { Description = "Path to a private key PEM file (ephemeral if omitted)" };
        var outputOption = new Option<string?>("--output") { Description = "Output path for the manifest file" };
        var labelOption = new Option<string?>("--label") { Description = "Label for this signature" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm (ephemeral default: ecdsa-p256)" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };
        var timestampOption = new Option<string?>("--timestamp") { Description = "TSA URL for RFC 3161 timestamping" };
        var includeOption = new Option<string?>("--include") { Description = "Glob filter for files (e.g. *.dll)" };

        var cmd = new Command("sign-manifest", "Sign multiple files with a shared manifest signature");
        cmd.Add(pathArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);
        cmd.Add(timestampOption);
        cmd.Add(includeOption);

        cmd.SetAction(async parseResult =>
        {
            var path = parseResult.GetValue(pathArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);
            var tsaUrl = parseResult.GetValue(timestampOption);
            var includeFilter = parseResult.GetValue(includeOption);

            // Resolve files from path
            var (basePath, filePaths) = ResolveFiles(path, includeFilter);
            if (basePath is null || filePaths is null)
                return;

            if (filePaths.Count == 0)
            {
                Console.Error.WriteLine("No files found matching the specified path.");
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

            var outputPath = output ?? Path.Combine(basePath, "manifest.sig.json");

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

                if (string.Equals(vaultName, "pkcs11", StringComparison.OrdinalIgnoreCase))
                    Console.Error.WriteLine("Waiting for PKCS#11 device (touch may be required)...");

                var envelope = await SignOrAppendAsync(basePath, filePaths, outputPath, signer, fingerprint, label);
                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

                var json = ManifestSigner.Serialize(envelope);
                File.WriteAllText(outputPath, json);

                WriteOutput(envelope, outputPath, signer, fingerprint, $"vault ({vaultName})");
                return;
            }

            // Local signing paths (PEM or ephemeral)
            ISigner localSigner;
            bool isEphemeral;

            if (keyPath is not null)
            {
                var loadResult = PemSignerLoader.Load(keyPath, passphrase, algorithmName);
                if (!loadResult.IsSuccess)
                {
                    Console.Error.WriteLine(loadResult.ErrorMessage);
                    return;
                }

                localSigner = loadResult.Value;
                isEphemeral = false;
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
                    Console.Error.WriteLine("Supported: ecdsa-p256, ecdsa-p384, rsa-pss-sha256, ml-dsa-65");
                    return;
                }

                localSigner = SignerFactory.Generate(algorithm);
                isEphemeral = true;
            }

            using (localSigner)
            {
                var fingerprint = KeyFingerprint.Compute(localSigner.PublicKey);

                var envelope = SignOrAppend(basePath, filePaths, outputPath, localSigner, fingerprint, label);
                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

                var json = ManifestSigner.Serialize(envelope);
                File.WriteAllText(outputPath, json);

                var mode = isEphemeral ? "ephemeral (key not persisted)" : "persistent";
                WriteOutput(envelope, outputPath, localSigner, fingerprint, mode);
            }
        });

        return cmd;
    }

    private static (string? basePath, List<string>? filePaths) ResolveFiles(string path, string? includeFilter)
    {
        if (Directory.Exists(path))
        {
            var basePath = Path.GetFullPath(path);
            var searchPattern = includeFilter ?? "*";
            var files = Directory.GetFiles(basePath, searchPattern, SearchOption.AllDirectories)
                .OrderBy(f => Path.GetRelativePath(basePath, f).Replace('\\', '/'), StringComparer.Ordinal)
                .ToList();

            return (basePath, files);
        }

        if (File.Exists(path))
        {
            var basePath = Path.GetDirectoryName(Path.GetFullPath(path))!;
            return (basePath, [Path.GetFullPath(path)]);
        }

        Console.Error.WriteLine($"Path not found: {path}");
        return (null, null);
    }

    private static ManifestEnvelope SignOrAppend(
        string basePath, List<string> filePaths, string outputPath,
        ISigner signer, KeyFingerprint fingerprint, string? label)
    {
        if (File.Exists(outputPath))
        {
            var existingJson = File.ReadAllText(outputPath);
            var envelope = ManifestSigner.Deserialize(existingJson);
            ManifestSigner.AppendSignature(envelope, signer, fingerprint, label);
            return envelope;
        }

        return ManifestSigner.Sign(basePath, filePaths, signer, fingerprint, label);
    }

    private static async Task<ManifestEnvelope> SignOrAppendAsync(
        string basePath, List<string> filePaths, string outputPath,
        ISigner signer, KeyFingerprint fingerprint, string? label)
    {
        if (File.Exists(outputPath))
        {
            var existingJson = await File.ReadAllTextAsync(outputPath).ConfigureAwait(false);
            var envelope = ManifestSigner.Deserialize(existingJson);
            await ManifestSigner.AppendSignatureAsync(envelope, signer, fingerprint, label).ConfigureAwait(false);
            return envelope;
        }

        return await ManifestSigner.SignAsync(basePath, filePaths, signer, fingerprint, label).ConfigureAwait(false);
    }

    private static async Task ApplyTimestampIfRequestedAsync(ManifestEnvelope envelope, string? tsaUrl)
    {
        if (tsaUrl is null)
            return;

        if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out var tsaUri))
        {
            Console.Error.WriteLine($"Warning: Invalid TSA URL: {tsaUrl}. Manifest saved without timestamp.");
            return;
        }

        var lastEntry = envelope.Signatures[^1];
        var result = await TimestampApplier.ApplyAsync(lastEntry, tsaUri).ConfigureAwait(false);

        if (result.IsSuccess)
        {
            envelope.Signatures[^1] = result.Value;
            var info = TimestampValidator.Validate(result.Value.TimestampToken!, Convert.FromBase64String(result.Value.Value));
            if (info.IsValid)
                Console.WriteLine($"Timestamp: {info.Timestamp:yyyy-MM-ddTHH:mm:ssZ} (verified)");
            else
                Console.Error.WriteLine($"Warning: Timestamp obtained but validation failed: {info.Error}");
        }
        else
        {
            Console.Error.WriteLine($"Warning: Timestamping failed ({result.ErrorMessage}). Manifest saved without timestamp.");
        }
    }

    private static void WriteOutput(
        ManifestEnvelope envelope, string outputPath,
        ISigner signer, KeyFingerprint fingerprint, string mode)
    {
        Console.WriteLine($"Manifest signed: {envelope.Subjects.Count} files");
        Console.WriteLine($"Algorithm: {signer.Algorithm.ToCanonicalName()}");
        Console.WriteLine($"Key: {fingerprint.ShortId}...");
        if (mode.Contains("ephemeral", StringComparison.Ordinal))
            Console.WriteLine($"Mode: {mode}");
        Console.WriteLine($"Output: {outputPath}");
    }
}
