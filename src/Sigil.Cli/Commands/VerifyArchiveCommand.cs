using System.CommandLine;
using System.Globalization;
using Sigil.Discovery;
using Sigil.Keyless;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class VerifyArchiveCommand
{
    public static Command Create()
    {
        var archiveArg = new Argument<string>("archive") { Description = "Path to the archive file" };
        var signatureOption = new Option<string?>("--signature") { Description = "Path to the signature file (default: <archive>.archive.sig.json)" };
        var trustBundleOption = new Option<string?>("--trust-bundle") { Description = "Path to a signed trust bundle for trust evaluation" };
        var authorityOption = new Option<string?>("--authority") { Description = "Expected authority fingerprint for the trust bundle" };
        var discoverOption = new Option<string?>("--discover") { Description = "Discover trust bundle from URI" };
        var policyOption = new Option<string?>("--policy") { Description = "Path to a policy file for rule-based verification" };
        var atOption = new Option<string?>("--at")
        {
            Description = "Evaluate trust as of a historical date (ISO 8601, e.g. 2025-06-15 or 2025-06-15T14:30:00Z)"
        };

        var cmd = new Command("verify-archive", "Verify an archive signature with per-entry digests");
        cmd.Add(archiveArg);
        cmd.Add(signatureOption);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);
        cmd.Add(policyOption);
        cmd.Add(atOption);

        cmd.SetAction(async parseResult =>
        {
            var archivePath = parseResult.GetValue(archiveArg)!;
            var signaturePath = parseResult.GetValue(signatureOption);
            var trustBundlePath = parseResult.GetValue(trustBundleOption);
            var authority = parseResult.GetValue(authorityOption);
            var discoverUri = parseResult.GetValue(discoverOption);
            var policyPath = parseResult.GetValue(policyOption);
            var atStr = parseResult.GetValue(atOption);
            DateTimeOffset? evaluationTime = null;
            if (atStr is not null)
            {
                if (!DateTimeOffset.TryParse(atStr, CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal, out var parsed))
                {
                    Console.Error.WriteLine($"Error: Invalid date format for --at: {atStr}");
                    Environment.ExitCode = 1;
                    return;
                }
                evaluationTime = parsed;
                Console.WriteLine($"Evaluating trust as of: {parsed:O}");
            }

            // Mutual exclusion check
            if (policyPath is not null && (trustBundlePath is not null || discoverUri is not null))
            {
                Console.Error.WriteLine("--policy is mutually exclusive with --trust-bundle and --discover.");
                return;
            }

            if (trustBundlePath is not null && discoverUri is not null)
            {
                Console.Error.WriteLine("--trust-bundle and --discover are mutually exclusive.");
                return;
            }

            if (!File.Exists(archivePath))
            {
                Console.Error.WriteLine($"Archive not found: {archivePath}");
                return;
            }

            signaturePath ??= archivePath + ".archive.sig.json";

            if (!File.Exists(signaturePath))
            {
                Console.Error.WriteLine($"Signature file not found: {signaturePath}");
                return;
            }

            var signatureJson = File.ReadAllText(signaturePath);
            ManifestEnvelope envelope;
            try
            {
                envelope = ArchiveSigner.Deserialize(signatureJson);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Console.Error.WriteLine($"Failed to parse signature: {ex.Message}");
                return;
            }

            var result = ArchiveValidator.Verify(archivePath, envelope);
            var verification = ArchiveValidator.ToVerificationResult(result);

            Console.WriteLine($"Archive: {Path.GetFileName(archivePath)} ({envelope.Subjects.Count} entries)");

            // Display per-entry results
            foreach (var entryResult in result.Entries)
            {
                if (entryResult.DigestMatch)
                {
                    Console.WriteLine($"  [OK] {entryResult.Name}");
                }
                else
                {
                    var reason = entryResult.Error is not null ? $" — {entryResult.Error}" : "";
                    Console.WriteLine($"  [FAIL] {entryResult.Name}{reason}");
                }
            }

            // Report extra entries
            if (result.ExtraEntries.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Extra entries (not in signature):");
                foreach (var extra in result.ExtraEntries)
                    Console.WriteLine($"  [WARN] {extra}");
            }

            // Policy evaluation
            if (policyPath is not null)
            {
                EvaluatePolicy(policyPath, verification, envelope);
                return;
            }

            // Discovery-based trust evaluation
            TrustEvaluationResult? trustResult = null;
            if (discoverUri is not null)
            {
                trustResult = await DiscoverAndEvaluateTrustAsync(discoverUri, authority, verification, envelope, evaluationTime);
            }
            else if (trustBundlePath is not null)
            {
                trustResult = await EvaluateTrustAsync(trustBundlePath, authority, verification, envelope, evaluationTime);
            }

            // Display signature results
            Console.WriteLine();
            Console.WriteLine("Signatures:");
            foreach (var sig in result.Signatures)
            {
                var status = sig.IsValid ? "VERIFIED" : "FAILED";
                var label = sig.Label is not null ? $" ({sig.Label})" : "";

                if (trustResult is not null)
                {
                    var trustSig = trustResult.Signatures
                        .FirstOrDefault(t => string.Equals(t.KeyId, sig.KeyId, StringComparison.Ordinal));

                    if (trustSig is not null)
                    {
                        var trustStatus = trustSig.Decision switch
                        {
                            TrustDecision.Trusted => "TRUSTED",
                            TrustDecision.TrustedViaEndorsement => "TRUSTED",
                            TrustDecision.TrustedViaOidc => "TRUSTED (OIDC)",
                            TrustDecision.Expired => "EXPIRED",
                            TrustDecision.ScopeMismatch => "SCOPE_MISMATCH",
                            TrustDecision.Revoked => "REVOKED",
                            _ => "UNTRUSTED"
                        };

                        var displayName = trustSig.DisplayName is not null
                            ? $" ({trustSig.DisplayName})"
                            : "";

                        Console.WriteLine($"  [{trustStatus}] {sig.KeyId}{displayName}{label}");

                        if (trustSig.Reason is not null)
                            Console.WriteLine($"           {trustSig.Reason}");
                    }
                    else
                    {
                        Console.WriteLine($"  [{status}] {sig.KeyId}{label}");
                    }
                }
                else
                {
                    Console.WriteLine($"  [{status}] {sig.KeyId}{label}");
                    if (sig.Error is not null)
                        Console.WriteLine($"           {sig.Error}");
                }

                if (sig.TimestampInfo is { IsValid: true } ts)
                    Console.WriteLine($"           Timestamp: {ts.Timestamp:yyyy-MM-ddTHH:mm:ssZ} (verified)");
                else if (sig.TimestampInfo is { IsValid: false } tsErr)
                    Console.WriteLine($"           Timestamp: INVALID ({tsErr.Error})");
            }

            // Summary
            if (trustResult is not null)
            {
                if (trustResult.AllTrusted)
                    Console.WriteLine("\nAll signatures TRUSTED.");
                else if (trustResult.AnyTrusted)
                    Console.WriteLine("\nSome signatures trusted, some untrusted.");
                else
                    Console.WriteLine("\nNo trusted signatures found.");
            }
            else
            {
                if (result.AllSignaturesValid)
                    Console.WriteLine("\nAll signatures VERIFIED.");
                else if (result.AnySignatureValid)
                    Console.WriteLine("\nSome signatures verified, some failed.");
                else
                    Console.WriteLine("\nNo valid signatures found.");
            }
        });

        return cmd;
    }

    private static async Task<TrustEvaluationResult?> DiscoverAndEvaluateTrustAsync(
        string discoverUri,
        string? authority,
        VerificationResult verification,
        ManifestEnvelope envelope,
        DateTimeOffset? evaluationTime = null)
    {
        var dispatcher = new DiscoveryDispatcher();
        var discoveryResult = await dispatcher.ResolveAsync(discoverUri);

        if (!discoveryResult.IsSuccess)
        {
            Console.Error.WriteLine($"Discovery failed: {discoveryResult.ErrorMessage}");
            return null;
        }

        var bundleJson = discoveryResult.Value;

        var deserializeResult = BundleSigner.Deserialize(bundleJson);
        if (!deserializeResult.IsSuccess)
        {
            Console.Error.WriteLine($"Failed to parse discovered trust bundle: {deserializeResult.ErrorMessage}");
            return null;
        }

        var bundle = deserializeResult.Value;

        var effectiveAuthority = authority;
        if (effectiveAuthority is null)
        {
            if (bundle.Signature is null)
            {
                Console.Error.WriteLine("Discovered trust bundle is unsigned. Use --authority or sign the bundle.");
                return null;
            }
            effectiveAuthority = bundle.Signature.KeyId;
        }

        var verifyResult = BundleSigner.Verify(bundleJson, effectiveAuthority);
        if (!verifyResult.IsSuccess)
        {
            Console.Error.WriteLine($"Trust bundle verification failed: {verifyResult.ErrorMessage}");
            return null;
        }

        if (!verifyResult.Value)
        {
            Console.Error.WriteLine("Trust bundle signature is invalid.");
            return null;
        }

        var oidcInfo = await VerifyOidcEntriesAsync(envelope);
        return TrustEvaluator.Evaluate(verification, bundle, null, evaluationTime: evaluationTime, oidcInfo: oidcInfo);
    }

    private static async Task<TrustEvaluationResult?> EvaluateTrustAsync(
        string trustBundlePath,
        string? authority,
        VerificationResult verification,
        ManifestEnvelope envelope,
        DateTimeOffset? evaluationTime = null)
    {
        if (!File.Exists(trustBundlePath))
        {
            Console.Error.WriteLine($"Trust bundle not found: {trustBundlePath}");
            return null;
        }

        var bundleJson = File.ReadAllText(trustBundlePath);

        var deserializeResult = BundleSigner.Deserialize(bundleJson);
        if (!deserializeResult.IsSuccess)
        {
            Console.Error.WriteLine($"Failed to parse trust bundle: {deserializeResult.ErrorMessage}");
            return null;
        }

        var bundle = deserializeResult.Value;

        if (authority is not null)
        {
            var verifyResult = BundleSigner.Verify(bundleJson, authority);
            if (!verifyResult.IsSuccess)
            {
                Console.Error.WriteLine($"Trust bundle verification failed: {verifyResult.ErrorMessage}");
                return null;
            }

            if (!verifyResult.Value)
            {
                Console.Error.WriteLine("Trust bundle signature is invalid.");
                return null;
            }
        }
        else if (bundle.Signature is not null)
        {
            Console.Error.WriteLine("--authority is required when using --trust-bundle with a signed bundle.");
            return null;
        }

        var oidcInfo = await VerifyOidcEntriesAsync(envelope);
        return TrustEvaluator.Evaluate(verification, bundle, null, evaluationTime: evaluationTime, oidcInfo: oidcInfo);
    }

    private static async Task<IReadOnlyDictionary<string, OidcVerificationInfo>?> VerifyOidcEntriesAsync(
        ManifestEnvelope envelope)
    {
        if (!envelope.Signatures.Any(s => s.OidcToken is not null))
            return null;

        using var verifier = new OidcVerifier();
        var results = await verifier.VerifyEntriesAsync(envelope.Signatures);
        return results.Count > 0 ? results : null;
    }

    private static void EvaluatePolicy(
        string policyPath,
        VerificationResult verification,
        ManifestEnvelope envelope)
    {
        if (!File.Exists(policyPath))
        {
            Console.Error.WriteLine($"Policy file not found: {policyPath}");
            return;
        }

        var json = File.ReadAllText(policyPath);
        var loadResult = PolicyLoader.Load(json);
        if (!loadResult.IsSuccess)
        {
            Console.Error.WriteLine($"Invalid policy: {loadResult.ErrorMessage}");
            return;
        }

        var context = new PolicyContext
        {
            Verification = verification,
            ManifestEnvelope = envelope,
            BasePath = Path.GetDirectoryName(Path.GetFullPath(policyPath))
        };

        var evalResult = PolicyEvaluator.Evaluate(loadResult.Value, context);

        Console.WriteLine("\nPolicy Evaluation:");
        foreach (var ruleResult in evalResult.Results)
        {
            var status = ruleResult.Passed ? "PASS" : "FAIL";
            Console.WriteLine($"  [{status}] {ruleResult.RuleName}");
            if (ruleResult.Reason is not null)
                Console.WriteLine($"         {ruleResult.Reason}");
        }

        if (evalResult.AllPassed)
            Console.WriteLine("\nAll policy rules PASSED.");
        else
            Console.WriteLine("\nPolicy evaluation FAILED.");
    }
}
