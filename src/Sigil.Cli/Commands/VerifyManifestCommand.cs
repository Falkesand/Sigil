using System.CommandLine;
using Sigil.Discovery;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class VerifyManifestCommand
{
    public static Command Create()
    {
        var manifestArg = new Argument<FileInfo>("manifest") { Description = "Path to the manifest signature file" };
        var basePathOption = new Option<string?>("--base-path") { Description = "Base directory for resolving files (default: manifest file's directory)" };
        var trustBundleOption = new Option<string?>("--trust-bundle") { Description = "Path to a signed trust bundle for trust evaluation" };
        var authorityOption = new Option<string?>("--authority") { Description = "Expected authority fingerprint for the trust bundle" };
        var discoverOption = new Option<string?>("--discover") { Description = "Discover trust bundle from URI" };
        var policyOption = new Option<string?>("--policy") { Description = "Path to a policy file for rule-based verification" };

        var cmd = new Command("verify-manifest", "Verify a manifest signature covering multiple files");
        cmd.Add(manifestArg);
        cmd.Add(basePathOption);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);
        cmd.Add(policyOption);

        cmd.SetAction(async parseResult =>
        {
            var manifestFile = parseResult.GetValue(manifestArg)!;
            var basePath = parseResult.GetValue(basePathOption);
            var trustBundlePath = parseResult.GetValue(trustBundleOption);
            var authority = parseResult.GetValue(authorityOption);
            var discoverUri = parseResult.GetValue(discoverOption);
            var policyPath = parseResult.GetValue(policyOption);

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

            if (!manifestFile.Exists)
            {
                Console.Error.WriteLine($"Manifest file not found: {manifestFile.FullName}");
                return;
            }

            var manifestJson = File.ReadAllText(manifestFile.FullName);
            ManifestEnvelope envelope;
            try
            {
                envelope = ManifestSigner.Deserialize(manifestJson);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to parse manifest: {ex.Message}");
                return;
            }

            basePath ??= Path.GetDirectoryName(manifestFile.FullName)!;

            var result = ManifestValidator.Verify(basePath, envelope);
            var verification = ManifestTrustAdapter.ToVerificationResult(result);

            Console.WriteLine($"Manifest: {manifestFile.Name} ({envelope.Subjects.Count} files)");

            // Display per-file results
            foreach (var fileResult in result.FileResults)
            {
                if (fileResult.DigestMatch)
                {
                    Console.WriteLine($"  [OK] {fileResult.Name}");
                }
                else
                {
                    var reason = fileResult.Error is not null ? $" — {fileResult.Error}" : "";
                    Console.WriteLine($"  [FAIL] {fileResult.Name}{reason}");
                }
            }

            // Policy evaluation
            if (policyPath is not null)
            {
                EvaluatePolicy(policyPath, verification, envelope, basePath);
                return;
            }

            // Discovery-based trust evaluation
            TrustEvaluationResult? trustResult = null;
            if (discoverUri is not null)
            {
                trustResult = await DiscoverAndEvaluateTrust(discoverUri, authority, verification);
            }
            else if (trustBundlePath is not null)
            {
                trustResult = EvaluateTrust(trustBundlePath, authority, verification);
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

    private static async Task<TrustEvaluationResult?> DiscoverAndEvaluateTrust(
        string discoverUri,
        string? authority,
        VerificationResult verification)
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

        return TrustEvaluator.Evaluate(verification, bundle, null);
    }

    private static TrustEvaluationResult? EvaluateTrust(
        string trustBundlePath,
        string? authority,
        VerificationResult verification)
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

        return TrustEvaluator.Evaluate(verification, bundle, null);
    }

    private static void EvaluatePolicy(
        string policyPath,
        VerificationResult verification,
        ManifestEnvelope envelope,
        string basePath)
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
