using System.CommandLine;
using System.Text.Json;
using Sigil.Attestation;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Timestamping;

namespace Sigil.Cli.Commands;

public static class AttestCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to attest" };
        var predicateOption = new Option<string>("--predicate") { Description = "Path to the predicate JSON file" };
        predicateOption.Required = true;
        var typeOption = new Option<string>("--type") { Description = "Predicate type (short name or URI)" };
        typeOption.Required = true;
        var keyOption = new Option<string?>("--key") { Description = "Path to a private key PEM file (ephemeral if omitted)" };
        var outputOption = new Option<string?>("--output") { Description = "Output path for the attestation file" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm (ephemeral default: ecdsa-p256)" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference" };
        var certStoreOption = new Option<string?>("--cert-store") { Description = "Certificate thumbprint for Windows Certificate Store" };
        var storeLocationOption = new Option<string?>("--store-location") { Description = "Store location: CurrentUser (default) or LocalMachine" };
        var timestampOption = new Option<string?>("--timestamp") { Description = "TSA URL for RFC 3161 timestamping" };

        var cmd = new Command("attest", "Create a DSSE attestation for an artifact");
        cmd.Add(artifactArg);
        cmd.Add(predicateOption);
        cmd.Add(typeOption);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);
        cmd.Add(certStoreOption);
        cmd.Add(storeLocationOption);
        cmd.Add(timestampOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var predicatePath = parseResult.GetValue(predicateOption)!;
            var typeName = parseResult.GetValue(typeOption)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);
            var certStoreThumbprint = parseResult.GetValue(certStoreOption);
            var storeLocationName = parseResult.GetValue(storeLocationOption);
            var tsaUrl = parseResult.GetValue(timestampOption);

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            if (!File.Exists(predicatePath))
            {
                Console.Error.WriteLine($"Predicate file not found: {predicatePath}");
                return;
            }

            // Resolve predicate type
            string predicateTypeUri;
            try
            {
                predicateTypeUri = PredicateTypeRegistry.Resolve(typeName);
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return;
            }

            // Parse predicate JSON
            JsonElement predicate;
            try
            {
                var predicateJson = File.ReadAllText(predicatePath);
                predicate = JsonSerializer.Deserialize<JsonElement>(predicateJson);
            }
            catch (JsonException ex)
            {
                Console.Error.WriteLine($"Invalid predicate JSON: {ex.Message}");
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

            var outputPath = output ?? artifact.FullName + ".att.json";

            // Create statement
            var statement = AttestationCreator.CreateStatement(
                artifact.FullName, predicateTypeUri, predicate);

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

                var envelope = await SignOrAppendAsync(outputPath, statement, signer, fingerprint);
                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

                WriteOutput(envelope, outputPath, artifact.Name, signer, fingerprint, $"vault ({vaultName})");
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
                var fingerprint = KeyFingerprint.Compute(certSigner.PublicKey);

                var envelope = await SignOrAppendAsync(outputPath, statement, certSigner, fingerprint);
                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

                WriteOutput(envelope, outputPath, artifact.Name, certSigner, fingerprint, "cert-store");
                return;
            }

            // Local signing paths (PEM or ephemeral)
            ISigner localSigner;
            bool isEphemeral;

            if (keyPath is not null)
            {
                var loadResult = KeyLoader.Load(keyPath, passphrase, algorithmName);
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
                    Console.Error.WriteLine("Supported: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-pss-sha256, ml-dsa-65");
                    return;
                }

                localSigner = SignerFactory.Generate(algorithm);
                isEphemeral = true;
            }

            using (localSigner)
            {
                var fingerprint = KeyFingerprint.Compute(localSigner.PublicKey);

                var envelope = SignOrAppend(outputPath, statement, localSigner, fingerprint);
                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

                var mode = isEphemeral ? "ephemeral (key not persisted)" : "persistent";
                WriteOutput(envelope, outputPath, artifact.Name, localSigner, fingerprint, mode);
            }
        });

        return cmd;
    }

    private static DsseEnvelope SignOrAppend(
        string outputPath, InTotoStatement statement, ISigner signer, KeyFingerprint fingerprint)
    {
        if (File.Exists(outputPath))
        {
            var existingJson = File.ReadAllText(outputPath);
            var deserializeResult = AttestationCreator.Deserialize(existingJson);
            if (deserializeResult.IsSuccess)
            {
                AttestationCreator.AppendSignature(deserializeResult.Value, signer, fingerprint);
                return deserializeResult.Value;
            }
        }

        return AttestationCreator.Sign(statement, signer, fingerprint);
    }

    private static async Task<DsseEnvelope> SignOrAppendAsync(
        string outputPath, InTotoStatement statement, ISigner signer, KeyFingerprint fingerprint)
    {
        if (File.Exists(outputPath))
        {
            var existingJson = await File.ReadAllTextAsync(outputPath).ConfigureAwait(false);
            var deserializeResult = AttestationCreator.Deserialize(existingJson);
            if (deserializeResult.IsSuccess)
            {
                await AttestationCreator.AppendSignatureAsync(deserializeResult.Value, signer, fingerprint)
                    .ConfigureAwait(false);
                return deserializeResult.Value;
            }
        }

        return await AttestationCreator.SignAsync(statement, signer, fingerprint).ConfigureAwait(false);
    }

    private static async Task ApplyTimestampIfRequestedAsync(DsseEnvelope envelope, string? tsaUrl)
    {
        if (tsaUrl is null)
            return;

        if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out var tsaUri))
        {
            Console.Error.WriteLine($"Warning: Invalid TSA URL: {tsaUrl}. Attestation saved without timestamp.");
            return;
        }

        var lastSig = envelope.Signatures[^1];
        var sigBytes = Convert.FromBase64String(lastSig.Sig);

        using var tsaClient = new TsaClient();
        var result = await tsaClient.RequestTimestampAsync(tsaUri, sigBytes).ConfigureAwait(false);

        if (result.IsSuccess)
        {
            var tokenBase64 = Convert.ToBase64String(result.Value);
            envelope.Signatures[^1] = new DsseSignature
            {
                KeyId = lastSig.KeyId,
                Sig = lastSig.Sig,
                Algorithm = lastSig.Algorithm,
                PublicKey = lastSig.PublicKey,
                Timestamp = lastSig.Timestamp,
                TimestampToken = tokenBase64
            };

            var info = TimestampValidator.Validate(tokenBase64, sigBytes);
            if (info.IsValid)
                Console.WriteLine($"Timestamp: {info.Timestamp:yyyy-MM-ddTHH:mm:ssZ} (verified)");
            else
                Console.Error.WriteLine($"Warning: Timestamp obtained but validation failed: {info.Error}");
        }
        else
        {
            Console.Error.WriteLine($"Warning: Timestamping failed ({result.ErrorMessage}). Attestation saved without timestamp.");
        }
    }

    private static void WriteOutput(
        DsseEnvelope envelope, string outputPath, string artifactName,
        ISigner signer, KeyFingerprint fingerprint, string mode)
    {
        var json = AttestationCreator.Serialize(envelope);
        File.WriteAllText(outputPath, json);

        Console.WriteLine($"Attested: {artifactName}");
        Console.WriteLine($"Algorithm: {signer.Algorithm.ToCanonicalName()}");
        Console.WriteLine($"Key: {fingerprint.ShortId}...");
        if (mode.Contains("ephemeral", StringComparison.Ordinal))
            Console.WriteLine($"Mode: {mode}");
        Console.WriteLine($"Attestation: {outputPath}");
    }
}
