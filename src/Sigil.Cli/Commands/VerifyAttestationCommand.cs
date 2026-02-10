using System.CommandLine;
using Sigil.Attestation;
using Sigil.Discovery;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class VerifyAttestationCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to verify" };
        var attestationOption = new Option<string?>("--attestation") { Description = "Path to the attestation file (default: <artifact>.att.json)" };
        var typeOption = new Option<string?>("--type") { Description = "Expected predicate type (short name or URI)" };
        var trustBundleOption = new Option<string?>("--trust-bundle") { Description = "Path to a signed trust bundle" };
        var authorityOption = new Option<string?>("--authority") { Description = "Expected authority fingerprint for the trust bundle" };
        var discoverOption = new Option<string?>("--discover") { Description = "Discover trust bundle from URI" };
        var policyOption = new Option<string?>("--policy") { Description = "Path to a policy file for rule-based verification" };

        var cmd = new Command("verify-attestation", "Verify a DSSE attestation for an artifact");
        cmd.Add(artifactArg);
        cmd.Add(attestationOption);
        cmd.Add(typeOption);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);
        cmd.Add(policyOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var attestationPath = parseResult.GetValue(attestationOption);
            var typeName = parseResult.GetValue(typeOption);
            var trustBundlePath = parseResult.GetValue(trustBundleOption);
            var authority = parseResult.GetValue(authorityOption);
            var discoverUri = parseResult.GetValue(discoverOption);
            var policyPath = parseResult.GetValue(policyOption);

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

            attestationPath ??= artifact.FullName + ".att.json";
            if (!File.Exists(attestationPath))
            {
                Console.Error.WriteLine($"Attestation file not found: {attestationPath}");
                return;
            }

            var attJson = File.ReadAllText(attestationPath);
            var deserializeResult = AttestationCreator.Deserialize(attJson);
            if (!deserializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Invalid attestation: {deserializeResult.ErrorMessage}");
                return;
            }

            var envelope = deserializeResult.Value;

            // Verify predicate type if specified
            if (typeName is not null)
            {
                string expectedUri;
                try
                {
                    expectedUri = PredicateTypeRegistry.Resolve(typeName);
                }
                catch (ArgumentException ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return;
                }

                var statementResult = AttestationCreator.ExtractStatement(envelope);
                if (statementResult.IsSuccess &&
                    !string.Equals(statementResult.Value.PredicateType, expectedUri, StringComparison.Ordinal))
                {
                    Console.Error.WriteLine($"Predicate type mismatch: expected '{expectedUri}', got '{statementResult.Value.PredicateType}'.");
                    return;
                }
            }

            var result = AttestationValidator.Verify(artifact.FullName, envelope);

            if (!result.SubjectDigestMatch)
            {
                Console.Error.WriteLine("FAILED: Subject digest mismatch — artifact has been modified.");
                return;
            }

            Console.WriteLine($"Artifact: {artifact.Name}");
            Console.WriteLine("Digests: MATCH");

            if (result.Statement is not null)
            {
                Console.WriteLine($"Predicate Type: {result.Statement.PredicateType}");
                Console.WriteLine($"Subjects: {result.Statement.Subject.Count}");
            }

            // Policy evaluation
            if (policyPath is not null)
            {
                var adapted = AttestationTrustAdapter.ToVerificationResult(result);
                EvaluatePolicy(policyPath, adapted, result.Statement, artifact.Name);
                return;
            }

            // Trust evaluation
            TrustEvaluationResult? trustResult = null;

            if (discoverUri is not null)
            {
                var adapted = AttestationTrustAdapter.ToVerificationResult(result);
                trustResult = await DiscoverAndEvaluateTrust(
                    discoverUri, authority, adapted, artifact.Name);
            }
            else if (trustBundlePath is not null)
            {
                var adapted = AttestationTrustAdapter.ToVerificationResult(result);
                trustResult = EvaluateTrust(trustBundlePath, authority, adapted, artifact.Name);
            }

            foreach (var sig in result.Signatures)
            {
                var status = sig.IsValid ? "VERIFIED" : "FAILED";

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

                        Console.WriteLine($"  [{trustStatus}] {sig.KeyId}{displayName}");

                        if (trustSig.Reason is not null)
                            Console.WriteLine($"           {trustSig.Reason}");
                    }
                    else
                    {
                        Console.WriteLine($"  [{status}] {sig.KeyId}");
                    }
                }
                else
                {
                    Console.WriteLine($"  [{status}] {sig.KeyId}");
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
        Signing.VerificationResult verification,
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

        return TrustEvaluator.Evaluate(verification, bundle, artifactName);
    }

    private static TrustEvaluationResult? EvaluateTrust(
        string trustBundlePath,
        string? authority,
        Signing.VerificationResult verification,
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

        return TrustEvaluator.Evaluate(verification, bundle, artifactName);
    }

    private static void EvaluatePolicy(
        string policyPath,
        VerificationResult verification,
        InTotoStatement? statement,
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
            Verification = verification,
            Statement = statement,
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
