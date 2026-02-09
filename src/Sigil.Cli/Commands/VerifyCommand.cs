using System.CommandLine;
using Sigil.Discovery;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class VerifyCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to verify" };
        var signatureOption = new Option<string?>("--signature") { Description = "Path to the signature file (default: <artifact>.sig.json)" };
        var trustBundleOption = new Option<string?>("--trust-bundle") { Description = "Path to a signed trust bundle for trust evaluation" };
        var authorityOption = new Option<string?>("--authority") { Description = "Expected authority fingerprint for the trust bundle" };
        var discoverOption = new Option<string?>("--discover") { Description = "Discover trust bundle from URI (well-known URL, dns:domain, or git:url)" };
        var policyOption = new Option<string?>("--policy") { Description = "Path to a policy file for rule-based verification" };

        var cmd = new Command("verify", "Verify the signature of an artifact");
        cmd.Add(artifactArg);
        cmd.Add(signatureOption);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);
        cmd.Add(policyOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var signaturePath = parseResult.GetValue(signatureOption);
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

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            signaturePath ??= artifact.FullName + ".sig.json";
            if (!File.Exists(signaturePath))
            {
                Console.Error.WriteLine($"Signature file not found: {signaturePath}");
                return;
            }

            var sigJson = File.ReadAllText(signaturePath);
            var envelope = ArtifactSigner.Deserialize(sigJson);

            var result = SignatureValidator.Verify(artifact.FullName, envelope);

            if (!result.ArtifactDigestMatch)
            {
                Console.Error.WriteLine("FAILED: Artifact digest mismatch — file has been modified.");
                return;
            }

            Console.WriteLine($"Artifact: {artifact.Name}");
            Console.WriteLine("Digests: MATCH");

            // Display SBOM metadata if present
            if (envelope.Subject.Metadata is { Count: > 0 } metadata)
            {
                if (metadata.TryGetValue("sbom.format", out var format))
                    Console.WriteLine($"SBOM Format: {format}");
                if (metadata.TryGetValue("sbom.specVersion", out var specVersion))
                    Console.WriteLine($"Spec Version: {specVersion}");
                if (metadata.TryGetValue("sbom.name", out var name))
                    Console.WriteLine($"Name: {name}");
                if (metadata.TryGetValue("sbom.version", out var version))
                    Console.WriteLine($"Version: {version}");
                if (metadata.TryGetValue("sbom.supplier", out var supplier))
                    Console.WriteLine($"Supplier: {supplier}");
                if (metadata.TryGetValue("sbom.serialNumber", out var serialNumber))
                    Console.WriteLine($"Serial Number: {serialNumber}");
                if (metadata.TryGetValue("sbom.componentCount", out var compCount))
                    Console.WriteLine($"Components: {compCount}");
            }

            // Policy evaluation
            if (policyPath is not null)
            {
                EvaluatePolicy(policyPath, result, envelope, artifact.Name);
                return;
            }

            // Discovery-based trust evaluation
            TrustEvaluationResult? trustResult = null;
            if (discoverUri is not null)
            {
                trustResult = await DiscoverAndEvaluateTrust(discoverUri, authority, result, envelope.Subject.Name);
            }
            // File-based trust evaluation
            else if (trustBundlePath is not null)
            {
                trustResult = EvaluateTrust(trustBundlePath, authority, result, envelope.Subject.Name);
            }

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
        VerificationResult verification,
        string? artifactName)
    {
        var dispatcher = new DiscoveryDispatcher();
        var discoveryResult = await dispatcher.ResolveAsync(discoverUri);

        if (!discoveryResult.IsSuccess)
        {
            Console.Error.WriteLine($"Discovery failed: {discoveryResult.ErrorMessage}");
            return null;
        }

        var bundleJson = discoveryResult.Value;

        // Deserialize to extract authority from bundle signature if not provided
        var deserializeResult = BundleSigner.Deserialize(bundleJson);
        if (!deserializeResult.IsSuccess)
        {
            Console.Error.WriteLine($"Failed to parse discovered trust bundle: {deserializeResult.ErrorMessage}");
            return null;
        }

        var bundle = deserializeResult.Value;

        // Auto-extract authority from bundle signature when --authority not specified
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

        // Verify bundle signature
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

        return TrustEvaluator.Evaluate(verification, bundle, artifactName);
    }

    private static TrustEvaluationResult? EvaluateTrust(
        string trustBundlePath,
        string? authority,
        VerificationResult verification,
        string? artifactName)
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

        // When authority is provided, verify bundle signature
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
            // Bundle is signed but no authority specified — require authority
            Console.Error.WriteLine("--authority is required when using --trust-bundle with a signed bundle.");
            return null;
        }

        return TrustEvaluator.Evaluate(verification, bundle, artifactName);
    }

    private static void EvaluatePolicy(
        string policyPath,
        VerificationResult result,
        SignatureEnvelope envelope,
        string? artifactName)
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
            Verification = result,
            Envelope = envelope,
            ArtifactName = artifactName,
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
