using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Policy;

public static class RuleEvaluator
{
    public static RuleResult EvaluateMinSignatures(PolicyRule rule, PolicyContext context)
    {
        var validCount = context.Verification.Signatures.Count(s => s.IsValid);
        var required = rule.Count!.Value;

        return new RuleResult
        {
            RuleName = "min-signatures",
            Passed = validCount >= required,
            Reason = validCount >= required
                ? $"{validCount} valid signature(s) meet minimum of {required}."
                : $"Only {validCount} valid signature(s), but {required} required."
        };
    }

    public static RuleResult EvaluateTimestamp(PolicyRule rule, PolicyContext context)
    {
        var validSigs = context.Verification.Signatures.Where(s => s.IsValid).ToList();

        if (validSigs.Count == 0)
        {
            return new RuleResult
            {
                RuleName = "timestamp",
                Passed = false,
                Reason = "No valid signatures to check for timestamps."
            };
        }

        var allTimestamped = validSigs.All(s => s.TimestampInfo is { IsValid: true });

        return new RuleResult
        {
            RuleName = "timestamp",
            Passed = allTimestamped,
            Reason = allTimestamped
                ? "All valid signatures have verified timestamps."
                : "One or more valid signatures are missing a verified timestamp."
        };
    }

    public static RuleResult EvaluateSbomMetadata(PolicyRule rule, PolicyContext context)
    {
        if (context.Envelope is null)
        {
            return new RuleResult
            {
                RuleName = "sbom-metadata",
                Passed = false,
                Reason = "SBOM metadata check is not applicable to attestation verification."
            };
        }

        var hasMetadata = context.Envelope.Subject.Metadata is { Count: > 0 } metadata
                          && metadata.ContainsKey("sbom.format");

        return new RuleResult
        {
            RuleName = "sbom-metadata",
            Passed = hasMetadata,
            Reason = hasMetadata
                ? "SBOM metadata is present."
                : "No SBOM metadata found in signature envelope."
        };
    }

    public static RuleResult EvaluateAlgorithm(PolicyRule rule, PolicyContext context)
    {
        var validSigs = context.Verification.Signatures.Where(s => s.IsValid).ToList();
        var allowed = rule.Allowed!;

        var disallowed = validSigs
            .Where(s => s.Algorithm is null ||
                        !allowed.Any(a => string.Equals(a, s.Algorithm, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (disallowed.Count == 0)
        {
            return new RuleResult
            {
                RuleName = "algorithm",
                Passed = true,
                Reason = "All valid signatures use approved algorithms."
            };
        }

        var names = string.Join(", ", disallowed.Select(s => s.Algorithm ?? "(unknown)"));
        return new RuleResult
        {
            RuleName = "algorithm",
            Passed = false,
            Reason = $"Disallowed algorithm(s): {names}."
        };
    }

    public static RuleResult EvaluateLabel(PolicyRule rule, PolicyContext context)
    {
        var pattern = rule.Match!;
        var anyMatch = context.Verification.Signatures
            .Where(s => s.IsValid)
            .Any(s => s.Label is not null && GlobMatcher.IsMatch(s.Label, pattern));

        return new RuleResult
        {
            RuleName = "label",
            Passed = anyMatch,
            Reason = anyMatch
                ? $"Found signature with label matching '{pattern}'."
                : $"No valid signature has a label matching '{pattern}'."
        };
    }

    public static RuleResult EvaluateTrusted(PolicyRule rule, PolicyContext context)
    {
        if (context.BasePath is null)
        {
            return new RuleResult
            {
                RuleName = "trusted",
                Passed = false,
                Reason = "Cannot resolve trust bundle: no base path available."
            };
        }

        // Validate bundle path to prevent directory traversal (OWASP A01)
        if (Path.IsPathRooted(rule.Bundle!) ||
            rule.Bundle!.Contains("..", StringComparison.Ordinal))
        {
            return new RuleResult
            {
                RuleName = "trusted",
                Passed = false,
                Reason = "Bundle path must be relative and cannot contain directory traversal."
            };
        }

        var bundlePath = Path.GetFullPath(Path.Combine(context.BasePath, rule.Bundle!));
        var fullBasePath = Path.GetFullPath(context.BasePath);

        if (!bundlePath.StartsWith(fullBasePath, StringComparison.OrdinalIgnoreCase))
        {
            return new RuleResult
            {
                RuleName = "trusted",
                Passed = false,
                Reason = "Bundle path must be within the policy directory."
            };
        }

        if (!File.Exists(bundlePath))
        {
            return new RuleResult
            {
                RuleName = "trusted",
                Passed = false,
                Reason = $"Trust bundle not found: {bundlePath}."
            };
        }

        var bundleJson = File.ReadAllText(bundlePath);

        var deserializeResult = BundleSigner.Deserialize(bundleJson);
        if (!deserializeResult.IsSuccess)
        {
            return new RuleResult
            {
                RuleName = "trusted",
                Passed = false,
                Reason = $"Failed to parse trust bundle: {deserializeResult.ErrorMessage}"
            };
        }

        var bundle = deserializeResult.Value;

        // Determine authority fingerprint
        var authority = rule.Authority;
        if (authority is null && bundle.Signature is not null)
        {
            authority = bundle.Signature.KeyId;
        }

        // Verify bundle signature if authority is available
        if (authority is not null)
        {
            var verifyResult = BundleSigner.Verify(bundleJson, authority);
            if (!verifyResult.IsSuccess || !verifyResult.Value)
            {
                return new RuleResult
                {
                    RuleName = "trusted",
                    Passed = false,
                    Reason = "Trust bundle signature verification failed."
                };
            }
        }

        var trustResult = TrustEvaluator.Evaluate(context.Verification, bundle, context.ArtifactName);

        return new RuleResult
        {
            RuleName = "trusted",
            Passed = trustResult.AnyTrusted,
            Reason = trustResult.AnyTrusted
                ? "At least one signature is trusted by the bundle."
                : "No signatures are trusted by the bundle."
        };
    }

    public static RuleResult EvaluateKey(PolicyRule rule, PolicyContext context)
    {
        var fingerprints = rule.Fingerprints!;
        var anyMatch = context.Verification.Signatures
            .Where(s => s.IsValid)
            .Any(s => fingerprints.Any(fp =>
                string.Equals(fp, s.KeyId, StringComparison.Ordinal)));

        return new RuleResult
        {
            RuleName = "key",
            Passed = anyMatch,
            Reason = anyMatch
                ? "Found signature from a required key."
                : "No valid signature matches the required fingerprints."
        };
    }
}
