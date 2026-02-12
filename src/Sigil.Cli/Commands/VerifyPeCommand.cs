using System.CommandLine;
using Sigil.Discovery;
using Sigil.Pe;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class VerifyPeCommand
{
    private const long MaxPeFileSize = 500 * 1024 * 1024; // 500 MB

    public static Command Create()
    {
        var peFileArg = new Argument<string>("pe-file") { Description = "Path to the PE binary (.exe, .dll)" };
        var signatureOption = new Option<string?>("--signature") { Description = "Path to the .sig.json envelope (default: <pe-file>.sig.json)" };
        var trustBundleOption = new Option<string?>("--trust-bundle") { Description = "Path to a signed trust bundle for trust evaluation" };
        var authorityOption = new Option<string?>("--authority") { Description = "Expected authority fingerprint for the trust bundle" };
        var discoverOption = new Option<string?>("--discover") { Description = "Discover trust bundle from URI" };
        var policyOption = new Option<string?>("--policy") { Description = "Path to a policy file for rule-based verification" };

        var cmd = new Command("verify-pe", "Verify Authenticode signature and Sigil envelope of a PE binary");
        cmd.Add(peFileArg);
        cmd.Add(signatureOption);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);
        cmd.Add(policyOption);

        cmd.SetAction(async parseResult =>
        {
            var peFilePath = parseResult.GetValue(peFileArg)!;
            var signaturePath = parseResult.GetValue(signatureOption);
            var trustBundlePath = parseResult.GetValue(trustBundleOption);
            var authority = parseResult.GetValue(authorityOption);
            var discoverUri = parseResult.GetValue(discoverOption);
            var policyPath = parseResult.GetValue(policyOption);

            // Mutual exclusion check
            if (policyPath is not null && (trustBundlePath is not null || discoverUri is not null))
            {
                Console.Error.WriteLine("--policy is mutually exclusive with --trust-bundle and --discover.");
                Environment.ExitCode = 1;
                return;
            }

            if (trustBundlePath is not null && discoverUri is not null)
            {
                Console.Error.WriteLine("--trust-bundle and --discover are mutually exclusive.");
                Environment.ExitCode = 1;
                return;
            }

            if (!File.Exists(peFilePath))
            {
                Console.Error.WriteLine($"PE file not found: {peFilePath}");
                Environment.ExitCode = 1;
                return;
            }

            var fileInfo = new FileInfo(peFilePath);
            if (fileInfo.Length > MaxPeFileSize)
            {
                Console.Error.WriteLine($"PE file too large: {fileInfo.Length:N0} bytes (max {MaxPeFileSize:N0}).");
                Environment.ExitCode = 1;
                return;
            }

            var peBytes = File.ReadAllBytes(peFilePath);

            Console.WriteLine($"PE file: {Path.GetFileName(peFilePath)}");

            // 1. Verify Authenticode signature
            var authResult = AuthenticodeVerifier.Verify(peBytes);
            Console.WriteLine();
            Console.WriteLine("Authenticode:");
            if (authResult.IsSuccess)
            {
                var auth = authResult.Value;
                if (auth.IsValid)
                {
                    Console.WriteLine("  [VERIFIED] Authenticode signature is valid");
                    Console.WriteLine($"  Subject: {auth.SubjectName}");
                    Console.WriteLine($"  Issuer: {auth.IssuerName}");
                    Console.WriteLine($"  Thumbprint: {auth.Thumbprint}");
                    Console.WriteLine($"  Digest: {auth.DigestAlgorithm}");
                    if (auth.TimestampUtc.HasValue)
                        Console.WriteLine($"  Timestamp: {auth.TimestampUtc.Value:yyyy-MM-ddTHH:mm:ssZ}");
                }
                else
                {
                    Console.WriteLine($"  [FAILED] {auth.Error}");
                }
            }
            else
            {
                Console.WriteLine($"  [ERROR] {authResult.ErrorMessage}");
            }

            // 2. Verify .sig.json envelope if it exists
            signaturePath ??= peFilePath + ".sig.json";
            if (File.Exists(signaturePath))
            {
                Console.WriteLine();
                Console.WriteLine("Sigil envelope:");

                SignatureEnvelope envelope;
                try
                {
                    var json = File.ReadAllText(signaturePath);
                    envelope = ArtifactSigner.Deserialize(json);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    Console.Error.WriteLine($"  [ERROR] Failed to parse .sig.json: {ex.Message}");
                    return;
                }

                var fileBytes = File.ReadAllBytes(peFilePath);
                var verification = SignatureValidator.Verify(fileBytes, envelope);

                // Policy evaluation
                if (policyPath is not null)
                {
                    EvaluatePolicy(policyPath, verification, envelope);
                    return;
                }

                // Trust evaluation
                TrustEvaluationResult? trustResult = null;
                if (discoverUri is not null)
                {
                    trustResult = await DiscoverAndEvaluateTrustAsync(
                        discoverUri, authority, verification);
                }
                else if (trustBundlePath is not null)
                {
                    trustResult = await EvaluateTrustAsync(
                        trustBundlePath, authority, verification);
                }

                // Display envelope verification results
                foreach (var sig in verification.Signatures)
                {
                    var status = sig.IsValid ? "VERIFIED" : "FAILED";
                    var labelStr = sig.Label is not null ? $" ({sig.Label})" : "";

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
                            Console.WriteLine($"  [{trustStatus}] {sig.KeyId}{labelStr}");
                            continue;
                        }
                    }

                    Console.WriteLine($"  [{status}] {sig.KeyId}{labelStr}");
                    if (sig.Error is not null)
                        Console.WriteLine($"           {sig.Error}");

                    if (sig.TimestampInfo is { IsValid: true } ts)
                        Console.WriteLine($"           Timestamp: {ts.Timestamp:yyyy-MM-ddTHH:mm:ssZ} (verified)");
                }

                if (trustResult is not null)
                {
                    if (trustResult.AllTrusted)
                        Console.WriteLine("\n  All envelope signatures TRUSTED.");
                    else
                        Console.WriteLine("\n  Not all envelope signatures trusted.");
                }
                else
                {
                    if (verification.Signatures.All(s => s.IsValid))
                        Console.WriteLine("\n  All envelope signatures VERIFIED.");
                    else
                        Console.WriteLine("\n  Envelope signature verification FAILED.");
                }
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"Sigil envelope: not found ({signaturePath})");
            }
        });

        return cmd;
    }

    private static async Task<TrustEvaluationResult?> DiscoverAndEvaluateTrustAsync(
        string discoverUri, string? authority, VerificationResult verification)
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

    private static async Task<TrustEvaluationResult?> EvaluateTrustAsync(
        string trustBundlePath, string? authority, VerificationResult verification)
    {
        if (!File.Exists(trustBundlePath))
        {
            Console.Error.WriteLine($"Trust bundle not found: {trustBundlePath}");
            return null;
        }

        var bundleJson = await File.ReadAllTextAsync(trustBundlePath).ConfigureAwait(false);
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
        string policyPath, VerificationResult verification, SignatureEnvelope envelope)
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
