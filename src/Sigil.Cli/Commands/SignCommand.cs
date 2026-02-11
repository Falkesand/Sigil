using System.CommandLine;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Keyless;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;
using Sigil.Transparency.Remote;

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
        var passphraseFileOption = new Option<string?>("--passphrase-file") { Description = "Path to file containing the passphrase" };
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm (ephemeral default: ecdsa-p256; also used as hint for encrypted PEM detection)" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider: hashicorp, azure, aws, gcp" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Vault key reference (format depends on provider)" };
        var timestampOption = new Option<string?>("--timestamp") { Description = "TSA URL for RFC 3161 timestamping" };
        var keylessOption = new Option<bool>("--keyless") { Description = "Use keyless/OIDC signing with ephemeral keys" };
        var oidcTokenOption = new Option<string?>("--oidc-token") { Description = "OIDC token for keyless signing (auto-detected from CI if omitted)" };
        var logUrlOption = new Option<string?>("--log-url") { Description = "Remote transparency log URL, or 'rekor' for Sigstore public log" };
        var logApiKeyOption = new Option<string?>("--log-api-key") { Description = "API key for Sigil log server (not needed for Rekor)" };
        var certStoreOption = new Option<string?>("--cert-store") { Description = "Certificate thumbprint for Windows Certificate Store" };
        var storeLocationOption = new Option<string?>("--store-location") { Description = "Store location: CurrentUser (default) or LocalMachine" };

        var cmd = new Command("sign", "Sign an artifact and produce a detached signature envelope");
        cmd.Add(artifactArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);
        cmd.Add(passphraseFileOption);
        cmd.Add(algorithmOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);
        cmd.Add(timestampOption);
        cmd.Add(keylessOption);
        cmd.Add(oidcTokenOption);
        cmd.Add(logUrlOption);
        cmd.Add(logApiKeyOption);
        cmd.Add(certStoreOption);
        cmd.Add(storeLocationOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var passphraseFile = parseResult.GetValue(passphraseFileOption);
            var algorithmName = parseResult.GetValue(algorithmOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);
            var tsaUrl = parseResult.GetValue(timestampOption);
            var keyless = parseResult.GetValue(keylessOption);
            var oidcToken = parseResult.GetValue(oidcTokenOption);
            var logUrl = parseResult.GetValue(logUrlOption);
            var logApiKey = parseResult.GetValue(logApiKeyOption);
            var certStoreThumbprint = parseResult.GetValue(certStoreOption);
            var storeLocationName = parseResult.GetValue(storeLocationOption);

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            // Validate mutual exclusivity
            if (keyless && keyPath is not null)
            {
                Console.Error.WriteLine("Cannot use both --keyless and --key. Choose one signing method.");
                return;
            }

            if (keyless && vaultName is not null)
            {
                Console.Error.WriteLine("Cannot use both --keyless and --vault. Choose one signing method.");
                return;
            }

            if (keyless && certStoreThumbprint is not null)
            {
                Console.Error.WriteLine("Cannot use both --keyless and --cert-store. Choose one signing method.");
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

            if (keyless && tsaUrl is null)
            {
                Console.Error.WriteLine("--timestamp is required for keyless signing (ephemeral keys need timestamps for trust).");
                return;
            }

            if (oidcToken is not null && !keyless)
            {
                Console.Error.WriteLine("--oidc-token requires --keyless.");
                return;
            }

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

            // Keyless/OIDC signing path
            if (keyless)
            {
                var ephemeralAlgorithmName = algorithmName ?? "ecdsa-p256";
                SigningAlgorithm keylessAlgorithm;
                try
                {
                    keylessAlgorithm = SigningAlgorithmExtensions.ParseAlgorithm(ephemeralAlgorithmName);
                }
                catch (ArgumentException)
                {
                    Console.Error.WriteLine($"Unknown algorithm: {ephemeralAlgorithmName}");
                    return;
                }

                var providerResult = OidcTokenProviderFactory.Create(oidcToken);
                if (!providerResult.IsSuccess)
                {
                    Console.Error.WriteLine($"OIDC error: {providerResult.ErrorMessage}");
                    return;
                }

                var keylessSignerResult = await KeylessSigner.CreateAsync(
                    providerResult.Value, keylessAlgorithm);
                if (!keylessSignerResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Keyless signing error: {keylessSignerResult.ErrorMessage}");
                    return;
                }

                using var keylessSigner = keylessSignerResult.Value;

                var outputPath = output ?? artifact.FullName + ".sig.json";
                var envelope = await ArtifactSigner.SignKeylessAsync(
                    artifact.FullName, keylessSigner, label);

                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);
                await SubmitToLogIfRequestedAsync(envelope, logUrl, logApiKey);

                var json = ArtifactSigner.Serialize(envelope);
                File.WriteAllText(outputPath, json);

                Console.WriteLine($"Signed: {artifact.Name}");
                Console.WriteLine($"Algorithm: {keylessSigner.Signer.Algorithm.ToCanonicalName()}");
                Console.WriteLine($"Mode: keyless ({providerResult.Value.ProviderName})");
                Console.WriteLine($"Identity: {keylessSigner.OidcIdentity} (from {keylessSigner.OidcIssuer})");
                if (envelope.Subject.Metadata?.TryGetValue("sbom.format", out var keylessSbomFormat) == true)
                    Console.WriteLine($"Format: {keylessSbomFormat} ({envelope.Subject.MediaType})");
                Console.WriteLine($"Signature: {outputPath}");
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
                await SubmitToLogIfRequestedAsync(envelope, logUrl, logApiKey);

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

                using var signer = signerResult.Value;
                var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

                var outputPath = output ?? artifact.FullName + ".sig.json";
                var envelope = await LoadOrCreateEnvelopeAsync(artifact, outputPath, signer, fingerprint, label);

                await ApplyTimestampIfRequestedAsync(envelope, tsaUrl);
                await SubmitToLogIfRequestedAsync(envelope, logUrl, logApiKey);

                var json = ArtifactSigner.Serialize(envelope);
                File.WriteAllText(outputPath, json);

                Console.WriteLine($"Signed: {artifact.Name}");
                Console.WriteLine($"Algorithm: {signer.Algorithm.ToCanonicalName()}");
                Console.WriteLine($"Key: {fingerprint.ShortId}...");
                Console.WriteLine("Mode: cert-store");
                if (envelope.Subject.Metadata?.TryGetValue("sbom.format", out var certSbomFormat) == true)
                    Console.WriteLine($"Format: {certSbomFormat} ({envelope.Subject.MediaType})");
                Console.WriteLine($"Signature: {outputPath}");
                return;
            }

            // Local signing paths (PEM, PFX, or ephemeral)
            ISigner localSigner;
            bool isEphemeral;

            if (keyPath is not null)
            {
                var resolvedPassphrase = PassphraseResolver.Resolve(passphrase, passphraseFile, keyPath: keyPath);
                var loadResult = KeyLoader.Load(keyPath, resolvedPassphrase, algorithmName);
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
                await SubmitToLogIfRequestedAsync(envelope, logUrl, logApiKey);

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

    private static async Task SubmitToLogIfRequestedAsync(
        SignatureEnvelope envelope, string? logUrl, string? logApiKey)
    {
        if (logUrl is null)
            return;

        IRemoteLog remoteLog;
        try
        {
            remoteLog = RemoteLogFactory.Create(logUrl, logApiKey);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"Warning: {ex.Message} Signature saved without log entry.");
            return;
        }

        using (remoteLog)
        {
            var lastEntry = envelope.Signatures[^1];
            var result = await LogSubmitter.SubmitAsync(
                lastEntry, envelope.Subject, remoteLog).ConfigureAwait(false);

            if (result.IsSuccess)
            {
                envelope.Signatures[^1] = result.Value;
                Console.WriteLine($"Logged: {remoteLog.LogUrl} (index {result.Value.TransparencyLogIndex})");
            }
            else
            {
                Console.Error.WriteLine($"Warning: Log submission failed ({result.ErrorMessage}). Signature saved without log entry.");
            }
        }
    }
}
