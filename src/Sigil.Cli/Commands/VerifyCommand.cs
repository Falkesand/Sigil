using System.CommandLine;
using Sigil.Discovery;
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

        var cmd = new Command("verify", "Verify the signature of an artifact");
        cmd.Add(artifactArg);
        cmd.Add(signatureOption);
        cmd.Add(trustBundleOption);
        cmd.Add(authorityOption);
        cmd.Add(discoverOption);

        cmd.SetAction(async parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var signaturePath = parseResult.GetValue(signatureOption);
            var trustBundlePath = parseResult.GetValue(trustBundleOption);
            var authority = parseResult.GetValue(authorityOption);
            var discoverUri = parseResult.GetValue(discoverOption);

            // Mutual exclusion check
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
                if (metadata.TryGetValue("sbom.componentCount", out var compCount))
                    Console.WriteLine($"Components: {compCount}");
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

        if (authority is null)
        {
            Console.Error.WriteLine("--authority is required when using --trust-bundle.");
            return null;
        }

        var bundleJson = File.ReadAllText(trustBundlePath);

        // Verify bundle signature against authority
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

        var deserializeResult = BundleSigner.Deserialize(bundleJson);
        if (!deserializeResult.IsSuccess)
        {
            Console.Error.WriteLine($"Failed to parse trust bundle: {deserializeResult.ErrorMessage}");
            return null;
        }

        return TrustEvaluator.Evaluate(verification, deserializeResult.Value, artifactName);
    }
}
