using System.CommandLine;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;

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
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm (ephemeral default: ecdsa-p256; also used as hint for encrypted PEM detection)" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };
        var timestampOption = new Option<string?>("--timestamp") { Description = "TSA URL for RFC 3161 timestamping" };

        var cmd = new Command("sign", "Sign an artifact and produce a detached signature envelope");
        cmd.Add(artifactArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);
        cmd.Add(timestampOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);
            var tsaUrl = parseResult.GetValue(timestampOption);

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

                if (string.Equals(vaultName, "pkcs11", StringComparison.OrdinalIgnoreCase))
                    Console.Error.WriteLine("Waiting for PKCS#11 device (touch may be required)...");

                var outputPath = output ?? artifact.FullName + ".sig.json";
                var envelope = await LoadOrCreateEnvelopeAsync(artifact, outputPath, signer, fingerprint, label);

                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

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
                // Ephemeral mode: generate key in memory
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

                var outputPath = output ?? artifact.FullName + ".sig.json";
                var envelope = LoadOrCreateEnvelope(artifact, outputPath, localSigner, fingerprint, label);

                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);

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
        });

        return cmd;
    }

    private static SignatureEnvelope LoadOrCreateEnvelope(
        FileInfo artifact, string outputPath, ISigner signer, KeyFingerprint fingerprint, string? label)
    {
        if (File.Exists(outputPath))
        {
            var existingJson = File.ReadAllText(outputPath);
            var envelope = ArtifactSigner.Deserialize(existingJson);
            var artifactBytes = File.ReadAllBytes(artifact.FullName);
            ArtifactSigner.AppendSignature(envelope, artifactBytes, signer, fingerprint, label);
            return envelope;
        }

        return ArtifactSigner.Sign(artifact.FullName, signer, fingerprint, label);
    }

    private static async Task ApplyTimestampIfRequestedAsync(SignatureEnvelope envelope, string? tsaUrl)
    {
        if (tsaUrl is null)
            return;

        if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out var tsaUri))
        {
            Console.Error.WriteLine($"Warning: Invalid TSA URL: {tsaUrl}. Signature saved without timestamp.");
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
            Console.Error.WriteLine($"Warning: Timestamping failed ({result.ErrorMessage}). Signature saved without timestamp.");
        }
    }

    private static async Task<SignatureEnvelope> LoadOrCreateEnvelopeAsync(
        FileInfo artifact, string outputPath, ISigner signer, KeyFingerprint fingerprint, string? label)
    {
        if (File.Exists(outputPath))
        {
            var existingJson = await File.ReadAllTextAsync(outputPath).ConfigureAwait(false);
            var envelope = ArtifactSigner.Deserialize(existingJson);
            var artifactBytes = await File.ReadAllBytesAsync(artifact.FullName).ConfigureAwait(false);
            await ArtifactSigner.AppendSignatureAsync(envelope, artifactBytes, signer, fingerprint, label).ConfigureAwait(false);
            return envelope;
        }

        return await ArtifactSigner.SignAsync(artifact.FullName, signer, fingerprint, label).ConfigureAwait(false);
    }
}
