using System.CommandLine;
using Sigil.Discovery;
using Sigil.Oci;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class VerifyImageCommand
{
    public static Command Create()
    {
        var imageArg = new Argument<string>("image") { Description = "Image reference (e.g., registry/repo:tag)" };
        var trustBundleOption = new Option<string?>("--trust-bundle") { Description = "Path to a signed trust bundle" };
        var authorityOption = new Option<string?>("--authority") { Description = "Expected authority fingerprint" };
        var discoverOption = new Option<string?>("--discover") { Description = "Discover trust bundle from URI" };
        var policyOption = new Option<string?>("--policy") { Description = "Path to a policy file" };

        var cmd = new Command("verify-image", "Verify signatures on an OCI container image");
        cmd.Add(imageArg);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);
        cmd.Add(policyOption);

        cmd.SetAction(async parseResult =>
        {
            var image = parseResult.GetValue(imageArg)!;
            var trustBundlePath = parseResult.GetValue(trustBundleOption);
            var authority = parseResult.GetValue(authorityOption);
            var discoverUri = parseResult.GetValue(discoverOption);
            var policyPath = parseResult.GetValue(policyOption);

            // Mutual exclusion checks
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

            // Parse image reference
            var refResult = ImageReference.Parse(image);
            if (!refResult.IsSuccess)
            {
                Console.Error.WriteLine($"Invalid image reference: {refResult.ErrorMessage}");
                return;
            }

            var imageRef = refResult.Value;
            var creds = RegistryCredentialResolver.Resolve(imageRef.Registry);

            using var registryClient = new OciRegistryClient(imageRef, creds);
            var result = await OciImageVerifier.VerifyAsync(registryClient, imageRef);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Verification failed: {result.ErrorMessage}");
                return;
            }

            var verificationResult = result.Value;
            Console.WriteLine($"Image: {imageRef.FullName}");
            Console.WriteLine($"Digest: {verificationResult.ManifestDigest}");
            Console.WriteLine($"Signatures: {verificationResult.SignatureCount}");
            Console.WriteLine();

            // Resolve trust bundle if requested
            TrustBundle? trustBundle = null;
            if (discoverUri is not null)
            {
                var (bundle, resolvedAuthority) = await DiscoverTrustBundleAsync(discoverUri, authority);
                trustBundle = bundle;
                authority = resolvedAuthority;
            }
            else if (trustBundlePath is not null)
            {
                trustBundle = LoadTrustBundle(trustBundlePath, authority);
            }

            // Policy evaluation
            if (policyPath is not null)
            {
                EvaluatePolicy(policyPath, verificationResult, imageRef.FullName);
                return;
            }

            // Display results with optional trust evaluation
            var index = 0;
            foreach (var sigResult in verificationResult.SignatureResults)
            {
                TrustEvaluationResult? trustEval = null;
                if (trustBundle is not null)
                    trustEval = TrustEvaluator.Evaluate(sigResult, trustBundle, imageRef.FullName);

                foreach (var sig in sigResult.Signatures)
                {
                    index++;

                    if (trustEval is not null)
                    {
                        var trustSig = trustEval.Signatures
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
                                ? $" ({trustSig.DisplayName})" : "";
                            Console.WriteLine($"  [{trustStatus}] Signature #{index}{displayName}");
                            if (trustSig.Reason is not null)
                                Console.WriteLine($"    Reason: {trustSig.Reason}");
                        }
                        else
                        {
                            var status = sig.IsValid ? "VERIFIED" : "FAILED";
                            Console.WriteLine($"  [{status}] Signature #{index}");
                        }
                    }
                    else
                    {
                        var status = sig.IsValid ? "VERIFIED" : "FAILED";
                        Console.WriteLine($"  [{status}] Signature #{index}");
                    }

                    Console.WriteLine($"    Key: {sig.KeyId[..Math.Min(12, sig.KeyId.Length)]}...");
                    if (sig.Algorithm is not null)
                        Console.WriteLine($"    Algorithm: {sig.Algorithm}");
                    if (sig.Label is not null)
                        Console.WriteLine($"    Label: {sig.Label}");
                    if (sig.TimestampInfo is { IsValid: true } ts)
                        Console.WriteLine($"    Timestamp: {ts.Timestamp:yyyy-MM-ddTHH:mm:ssZ}");
                    if (sig.Error is not null)
                        Console.WriteLine($"    Error: {sig.Error}");
                }
            }

            Console.WriteLine();
            if (verificationResult.AllSignaturesValid)
                Console.WriteLine("All signatures VERIFIED.");
            else if (verificationResult.AnySignatureValid)
                Console.WriteLine("Some signatures verified, some failed.");
            else
                Console.WriteLine("No valid signatures found.");
        });

        return cmd;
    }

    private static async Task<(TrustBundle? Bundle, string? Authority)> DiscoverTrustBundleAsync(
        string discoverUri, string? authority)
    {
        var dispatcher = new DiscoveryDispatcher();
        var discoveryResult = await dispatcher.ResolveAsync(discoverUri);
        if (!discoveryResult.IsSuccess)
        {
            Console.Error.WriteLine($"Discovery failed: {discoveryResult.ErrorMessage}");
            return (null, authority);
        }

        var bundleJson = discoveryResult.Value;
        var deserializeResult = BundleSigner.Deserialize(bundleJson);
        if (!deserializeResult.IsSuccess)
        {
            Console.Error.WriteLine($"Failed to parse discovered trust bundle: {deserializeResult.ErrorMessage}");
            return (null, authority);
        }

        var bundle = deserializeResult.Value;

        // Auto-extract authority from bundle signature when not specified
        if (authority is null)
        {
            if (bundle.Signature is null)
            {
                Console.Error.WriteLine("Discovered trust bundle is unsigned. Use --authority or sign the bundle.");
                return (null, authority);
            }
            authority = bundle.Signature.KeyId;
        }

        var verifyResult = BundleSigner.Verify(bundleJson, authority);
        if (!verifyResult.IsSuccess)
        {
            Console.Error.WriteLine($"Trust bundle verification failed: {verifyResult.ErrorMessage}");
            return (null, authority);
        }

        if (!verifyResult.Value)
        {
            Console.Error.WriteLine("Trust bundle signature is invalid.");
            return (null, authority);
        }

        return (bundle, authority);
    }

    private static TrustBundle? LoadTrustBundle(string path, string? authority)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"Trust bundle not found: {path}");
            return null;
        }

        var bundleJson = File.ReadAllText(path);

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

        return bundle;
    }

    private static void EvaluatePolicy(
        string policyPath, OciVerificationResult ociResult, string imageName)
    {
        if (!File.Exists(policyPath))
        {
            Console.Error.WriteLine($"Policy file not found: {policyPath}");
            return;
        }

        var json = File.ReadAllText(policyPath);
        var loadResult = Policy.PolicyLoader.Load(json);
        if (!loadResult.IsSuccess)
        {
            Console.Error.WriteLine($"Invalid policy: {loadResult.ErrorMessage}");
            return;
        }

        Console.WriteLine("Policy Evaluation:");

        // Evaluate each signature result against the policy
        foreach (var sigResult in ociResult.SignatureResults)
        {
            var context = new Policy.PolicyContext
            {
                Verification = sigResult,
                ArtifactName = imageName,
                BasePath = Path.GetDirectoryName(Path.GetFullPath(policyPath))
            };

            var evalResult = Policy.PolicyEvaluator.Evaluate(loadResult.Value, context);

            foreach (var ruleResult in evalResult.Results)
            {
                var status = ruleResult.Passed ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {ruleResult.RuleName}");
                if (ruleResult.Reason is not null)
                    Console.WriteLine($"         {ruleResult.Reason}");
            }
        }
    }
}
