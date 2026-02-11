using System.Globalization;
using System.Text;
using System.Text.Json;
using Sigil.Cli.Vault;
using Sigil.Crypto;
using Sigil.Git;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Vault;
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace Sigil.Cli.Commands;

/// <summary>
/// GPG-compatible entry point for git signing/verification.
/// Bypasses System.CommandLine because git passes GPG-style args
/// (--status-fd=2 -bsau keyid) that don't conform to System.CommandLine conventions.
/// </summary>
public static class GitSignProgram
{
    /// <summary>
    /// Returns true if this argument list should be handled by GitSignProgram
    /// instead of System.CommandLine.
    /// </summary>
    public static bool ShouldIntercept(string[] args)
    {
        return args.Length > 0
            && string.Equals(args[0], "git-sign", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Runs the git-sign program with the given arguments (after "git-sign").
    /// Returns the process exit code.
    /// </summary>
    public static async Task<int> RunAsync(string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        // Parse args after "git-sign"
        var parsed = ParseArgs(args.AsSpan(1));

        // Validate mutual exclusivity: --key vs --vault/--vault-key vs --cert-store
        if (parsed.KeyPath is not null && parsed.VaultName is not null)
        {
            stderr.WriteLine("Error: Cannot use both --key and --vault. Choose one signing method.");
            return 1;
        }

        if (parsed.VaultName is not null && parsed.VaultKey is null)
        {
            stderr.WriteLine("Error: --vault-key is required when using --vault.");
            return 1;
        }

        if (parsed.VaultKey is not null && parsed.VaultName is null)
        {
            stderr.WriteLine("Error: --vault is required when using --vault-key.");
            return 1;
        }

        if (parsed.CertStoreThumbprint is not null && parsed.KeyPath is not null)
        {
            stderr.WriteLine("Error: Cannot use both --key and --cert-store. Choose one signing method.");
            return 1;
        }

        if (parsed.CertStoreThumbprint is not null && parsed.VaultName is not null)
        {
            stderr.WriteLine("Error: Cannot use both --vault and --cert-store. Choose one signing method.");
            return 1;
        }

        if (parsed.StoreLocation is not null && parsed.CertStoreThumbprint is null)
        {
            stderr.WriteLine("Error: --store-location requires --cert-store.");
            return 1;
        }

        if (parsed.VerifyFile is not null)
        {
            return RunVerify(parsed, stdin, stdout, stderr);
        }

        if (parsed.KeyPath is null && parsed.VaultName is null && parsed.CertStoreThumbprint is null)
        {
            stderr.WriteLine("Error: --key, --vault/--vault-key, or --cert-store required for git-sign.");
            return 1;
        }

        return await RunSignAsync(parsed, stdin, stdout, stderr);
    }

    private static async Task<int> RunSignAsync(ParsedArgs parsed, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        // Read commit/tag content from stdin
        var content = stdin.ReadToEnd();
        if (string.IsNullOrEmpty(content))
        {
            stderr.WriteLine("Error: No data received on stdin.");
            return 1;
        }

        // Normalize git content: git sends content WITH a blank line (header/body separator)
        // during signing, but WITHOUT it during verification (gpgsig stripping consumes it).
        // Remove the blank line so the stored digest matches verification content.
        var contentBytes = NormalizeGitContent(Encoding.UTF8.GetBytes(content));

        ISigner? signer = null;
        IKeyProvider? provider = null;

        try
        {
            if (parsed.VaultName is not null)
            {
                // Vault path
                var createResult = VaultProviderFactory.Create(parsed.VaultName);
                if (!createResult.IsSuccess)
                {
                    stderr.WriteLine($"Error: {createResult.ErrorMessage}");
                    return 1;
                }

                provider = createResult.Value;

                var signerResult = await provider.GetSignerAsync(parsed.VaultKey!);
                if (!signerResult.IsSuccess)
                {
                    stderr.WriteLine($"Error: {signerResult.ErrorMessage}");
                    return 1;
                }

                signer = signerResult.Value;
            }
            else if (parsed.CertStoreThumbprint is not null)
            {
                // Certificate store path (Windows only)
                if (!OperatingSystem.IsWindows())
                {
                    stderr.WriteLine("Error: --cert-store is only supported on Windows.");
                    return 1;
                }

                var storeLocation = parsed.StoreLocation is not null
                    ? Enum.Parse<StoreLocation>(parsed.StoreLocation, ignoreCase: true)
                    : StoreLocation.CurrentUser;

                provider = new CertStoreKeyProvider(storeLocation);
                var signerResult = await provider.GetSignerAsync(parsed.CertStoreThumbprint);
                if (!signerResult.IsSuccess)
                {
                    stderr.WriteLine($"Error: {signerResult.ErrorMessage}");
                    return 1;
                }

                signer = signerResult.Value;
            }
            else
            {
                // PEM/PFX path — resolve passphrase via centralized resolver
                var passphrase = PassphraseResolver.Resolve(
                    parsed.Passphrase, parsed.PassphraseFile,
                    allowInteractivePrompt: false);

                var loadResult = KeyLoader.Load(parsed.KeyPath!, passphrase, null);
                if (!loadResult.IsSuccess)
                {
                    stderr.WriteLine($"Error: {loadResult.ErrorMessage}");
                    return 1;
                }

                signer = loadResult.Value;
            }

            var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
            var algorithm = signer.Algorithm.ToCanonicalName();
            var now = DateTimeOffset.UtcNow;
            var timestamp = now.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

            // Compute digests
            var (sha256, sha512) = HashAlgorithms.ComputeDigests(contentBytes);

            // Build subject
            var subject = new SubjectDescriptor
            {
                Name = "git-object",
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                }
            };

            // Build signing payload
            var version = "1.0";
            var payload = ArtifactSigner.BuildSigningPayload(
                subject, contentBytes, version,
                fingerprint.Value, algorithm, timestamp, null);

            // Sign (async for vault, DIM delegates to sync for local)
            if (string.Equals(parsed.VaultName, "pkcs11", StringComparison.OrdinalIgnoreCase))
                stderr.WriteLine("Waiting for PKCS#11 device (touch may be required)...");

            var signatureBytes = await signer.SignAsync(payload);

            // Build envelope
            var entry = new SignatureEntry
            {
                KeyId = fingerprint.Value,
                Algorithm = algorithm,
                PublicKey = Convert.ToBase64String(signer.PublicKey),
                Value = Convert.ToBase64String(signatureBytes),
                Timestamp = timestamp
            };

            var envelope = new SignatureEnvelope
            {
                Subject = subject,
                Signatures = [entry]
            };

            // Serialize and armor
            var json = ArtifactSigner.Serialize(envelope);
            var armored = GitSignatureArmor.Wrap(json);

            // Write armored signature to stdout
            stdout.Write(armored);

            // Write GPG status to status-fd
            var statusWriter = GetStatusWriter(parsed.StatusFd, stdout, stderr);
            statusWriter.WriteLine(GpgStatusEmitter.SigCreated(algorithm, fingerprint.Value, now));

            return 0;
        }
        finally
        {
            if (signer is IDisposable disposableSigner)
                disposableSigner.Dispose();

            if (provider is IAsyncDisposable asyncDisposableProvider)
                await asyncDisposableProvider.DisposeAsync();
        }
    }

    private static int RunVerify(ParsedArgs parsed, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        // Read armored signature from verify file
        string armored;
        try
        {
            armored = File.ReadAllText(parsed.VerifyFile!);
        }
        catch (IOException ex)
        {
            stderr.WriteLine($"Error: Cannot read signature file: {ex.Message}");
            return 1;
        }

        // Unwrap armor
        var unwrapResult = GitSignatureArmor.Unwrap(armored);
        if (!unwrapResult.IsSuccess)
        {
            stderr.WriteLine($"Error: {unwrapResult.ErrorMessage}");
            return 1;
        }

        // Parse envelope
        SignatureEnvelope envelope;
        try
        {
            envelope = ArtifactSigner.Deserialize(unwrapResult.Value);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            stderr.WriteLine($"Error: Invalid signature envelope: {ex.Message}");
            return 1;
        }

        // Read commit/tag content from stdin
        // Normalize: git sends content WITHOUT blank line during verification
        // (gpgsig stripping consumes it). Signing also normalizes, so both paths match.
        var content = stdin.ReadToEnd();
        var contentBytes = NormalizeGitContent(Encoding.UTF8.GetBytes(content));

        // Verify using the standard SignatureValidator
        var result = SignatureValidator.Verify(contentBytes, envelope);

        var statusWriter = GetStatusWriter(parsed.StatusFd, stdout, stderr);

        // NEWSIG must precede GOODSIG/BADSIG — git checks for "\n[GNUPG:] GOODSIG"
        statusWriter.WriteLine(GpgStatusEmitter.NewSig());

        if (result.AllSignaturesValid)
        {
            var sig = envelope.Signatures[0];
            var keyId = sig.KeyId;
            statusWriter.WriteLine(GpgStatusEmitter.GoodSig(keyId));

            if (DateTimeOffset.TryParseExact(sig.Timestamp, "yyyy-MM-ddTHH:mm:ssZ",
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts))
            {
                statusWriter.WriteLine(GpgStatusEmitter.ValidSig(keyId, ts, sig.Algorithm));
            }

            statusWriter.WriteLine(GpgStatusEmitter.TrustUndefined());
            return 0;
        }

        // Verification failed
        var failKeyId = envelope.Signatures.Count > 0 ? envelope.Signatures[0].KeyId : "unknown";
        statusWriter.WriteLine(GpgStatusEmitter.BadSig(failKeyId));
        return 1;
    }

    private static TextWriter GetStatusWriter(int statusFd, TextWriter stdout, TextWriter stderr)
    {
        return statusFd switch
        {
            1 => stdout,
            _ => stderr // default to stderr (fd 2)
        };
    }

    private static ParsedArgs ParseArgs(ReadOnlySpan<string> args)
    {
        string? keyPath = null;
        string? passphrase = null;
        string? passphraseFile = null;
        string? verifyFile = null;
        string? vaultName = null;
        string? vaultKey = null;
        string? certStoreThumbprint = null;
        string? storeLocation = null;
        int statusFd = 2;

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg.StartsWith("--key=", StringComparison.OrdinalIgnoreCase))
            {
                keyPath = arg["--key=".Length..];
            }
            else if (string.Equals(arg, "--key", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                keyPath = args[++i];
            }
            else if (arg.StartsWith("--passphrase=", StringComparison.OrdinalIgnoreCase))
            {
                passphrase = arg["--passphrase=".Length..];
            }
            else if (string.Equals(arg, "--passphrase", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                passphrase = args[++i];
            }
            else if (arg.StartsWith("--passphrase-file=", StringComparison.OrdinalIgnoreCase))
            {
                passphraseFile = arg["--passphrase-file=".Length..];
            }
            else if (string.Equals(arg, "--passphrase-file", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                passphraseFile = args[++i];
            }
            else if (arg.StartsWith("--vault=", StringComparison.OrdinalIgnoreCase))
            {
                vaultName = arg["--vault=".Length..];
            }
            else if (string.Equals(arg, "--vault", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                vaultName = args[++i];
            }
            else if (arg.StartsWith("--vault-key=", StringComparison.OrdinalIgnoreCase))
            {
                vaultKey = arg["--vault-key=".Length..];
            }
            else if (string.Equals(arg, "--vault-key", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                vaultKey = args[++i];
            }
            else if (arg.StartsWith("--status-fd=", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(arg["--status-fd=".Length..], CultureInfo.InvariantCulture, out var fd))
                    statusFd = fd;
            }
            else if (arg.StartsWith("--cert-store=", StringComparison.OrdinalIgnoreCase))
            {
                certStoreThumbprint = arg["--cert-store=".Length..];
            }
            else if (string.Equals(arg, "--cert-store", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                certStoreThumbprint = args[++i];
            }
            else if (arg.StartsWith("--store-location=", StringComparison.OrdinalIgnoreCase))
            {
                storeLocation = arg["--store-location=".Length..];
            }
            else if (string.Equals(arg, "--store-location", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                storeLocation = args[++i];
            }
            else if (string.Equals(arg, "--verify", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                verifyFile = args[++i];
            }
            // Ignore GPG-compat args: -bsau, -b, -s, -a, -u, and their values
        }

        return new ParsedArgs(keyPath, passphrase, passphraseFile, verifyFile, statusFd, vaultName, vaultKey, certStoreThumbprint, storeLocation);
    }

    /// <summary>
    /// Normalizes git commit/tag content for signing.
    /// Git sends content WITH a blank line (header/body separator) during signing,
    /// but WITHOUT it during verification (gpgsig header stripping consumes it).
    /// This method removes the first blank line so the digest matches both paths.
    /// </summary>
    internal static byte[] NormalizeGitContent(byte[] content)
    {
        // Find the first \n\n sequence (header/body separator in git objects)
        for (int i = 0; i < content.Length - 1; i++)
        {
            if (content[i] == (byte)'\n' && content[i + 1] == (byte)'\n')
            {
                // Remove one \n — shift everything after index i+1 left by 1
                var result = new byte[content.Length - 1];
                Buffer.BlockCopy(content, 0, result, 0, i + 1);
                Buffer.BlockCopy(content, i + 2, result, i + 1, content.Length - i - 2);
                return result;
            }
        }

        // No blank line found — return as-is (shouldn't happen for valid git objects)
        return content;
    }

    private sealed record ParsedArgs(
        string? KeyPath,
        string? Passphrase,
        string? PassphraseFile,
        string? VerifyFile,
        int StatusFd,
        string? VaultName,
        string? VaultKey,
        string? CertStoreThumbprint,
        string? StoreLocation);
}
