using System.Globalization;
using System.Text;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Git;
using Sigil.Keys;
using Sigil.Signing;

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
    public static int Run(string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        // Parse args after "git-sign"
        var parsed = ParseArgs(args.AsSpan(1));

        if (parsed.KeyPath is null)
        {
            stderr.WriteLine("Error: --key is required for git-sign.");
            return 1;
        }

        if (parsed.VerifyFile is not null)
        {
            return RunVerify(parsed, stdin, stdout, stderr);
        }

        return RunSign(parsed, stdin, stdout, stderr);
    }

    private static int RunSign(ParsedArgs parsed, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        // Read commit/tag content from stdin
        var content = stdin.ReadToEnd();
        if (string.IsNullOrEmpty(content))
        {
            stderr.WriteLine("Error: No data received on stdin.");
            return 1;
        }

        var contentBytes = Encoding.UTF8.GetBytes(content);

        // Load signer from PEM
        var loadResult = PemSignerLoader.Load(parsed.KeyPath!, parsed.Passphrase, null);
        if (!loadResult.IsSuccess)
        {
            stderr.WriteLine($"Error: {loadResult.ErrorMessage}");
            return 1;
        }

        using var signer = loadResult.Value;
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

        // Sign
        var signatureBytes = signer.Sign(payload);

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
        var content = stdin.ReadToEnd();
        var contentBytes = Encoding.UTF8.GetBytes(content);

        // Verify using the standard SignatureValidator
        var result = SignatureValidator.Verify(contentBytes, envelope);

        var statusWriter = GetStatusWriter(parsed.StatusFd, stdout, stderr);

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
        string? verifyFile = null;
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
            else if (arg.StartsWith("--status-fd=", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(arg["--status-fd=".Length..], CultureInfo.InvariantCulture, out var fd))
                    statusFd = fd;
            }
            else if (string.Equals(arg, "--verify", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                verifyFile = args[++i];
            }
            // Ignore GPG-compat args: -bsau, -b, -s, -a, -u, and their values
        }

        return new ParsedArgs(keyPath, passphrase, verifyFile, statusFd);
    }

    private sealed record ParsedArgs(
        string? KeyPath,
        string? Passphrase,
        string? VerifyFile,
        int StatusFd);
}
