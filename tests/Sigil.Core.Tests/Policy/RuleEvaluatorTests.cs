using Sigil.Attestation;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Core.Tests.Policy;

public class RuleEvaluatorTests
{
    // --- min-signatures ---

    [Fact]
    public void MinSignatures_EnoughValid_Passes()
    {
        var context = CreateContext(validSigCount: 2);
        var rule = new PolicyRule { Require = "min-signatures", Count = 2 };

        var result = RuleEvaluator.EvaluateMinSignatures(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MinSignatures_NotEnoughValid_Fails()
    {
        var context = CreateContext(validSigCount: 1);
        var rule = new PolicyRule { Require = "min-signatures", Count = 2 };

        var result = RuleEvaluator.EvaluateMinSignatures(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("1", result.Reason!);
    }

    [Fact]
    public void MinSignatures_InvalidSigsNotCounted()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256" },
            new() { KeyId = "k2", IsValid = false, Algorithm = "ecdsa-p256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "min-signatures", Count = 2 };

        var result = RuleEvaluator.EvaluateMinSignatures(rule, context);

        Assert.False(result.Passed);
    }

    // --- timestamp ---

    [Fact]
    public void Timestamp_AllValid_Passes()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256",
                     TimestampInfo = new TimestampVerificationInfo { IsValid = true, Timestamp = DateTimeOffset.UtcNow } }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "timestamp" };

        var result = RuleEvaluator.EvaluateTimestamp(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Timestamp_MissingTimestamp_Fails()
    {
        var context = CreateContext(validSigCount: 1);
        var rule = new PolicyRule { Require = "timestamp" };

        var result = RuleEvaluator.EvaluateTimestamp(rule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Timestamp_InvalidTimestamp_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256",
                     TimestampInfo = new TimestampVerificationInfo { IsValid = false, Timestamp = DateTimeOffset.UtcNow, Error = "bad" } }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "timestamp" };

        var result = RuleEvaluator.EvaluateTimestamp(rule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Timestamp_InvalidSigsSkipped()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256",
                     TimestampInfo = new TimestampVerificationInfo { IsValid = true, Timestamp = DateTimeOffset.UtcNow } },
            new() { KeyId = "k2", IsValid = false, Algorithm = "ecdsa-p256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "timestamp" };

        var result = RuleEvaluator.EvaluateTimestamp(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Timestamp_NoValidSigs_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = false, Algorithm = "ecdsa-p256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "timestamp" };

        var result = RuleEvaluator.EvaluateTimestamp(rule, context);

        Assert.False(result.Passed);
    }

    // --- sbom-metadata ---

    [Fact]
    public void SbomMetadata_Present_Passes()
    {
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.json",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" },
                Metadata = new Dictionary<string, string> { ["sbom.format"] = "CycloneDX" }
            }
        };
        var context = CreateContext(validSigCount: 1, envelope: envelope);
        var rule = new PolicyRule { Require = "sbom-metadata" };

        var result = RuleEvaluator.EvaluateSbomMetadata(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SbomMetadata_Missing_Fails()
    {
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.json",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            }
        };
        var context = CreateContext(validSigCount: 1, envelope: envelope);
        var rule = new PolicyRule { Require = "sbom-metadata" };

        var result = RuleEvaluator.EvaluateSbomMetadata(rule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void SbomMetadata_NoEnvelope_Fails()
    {
        var context = CreateContext(validSigCount: 1);
        var rule = new PolicyRule { Require = "sbom-metadata" };

        var result = RuleEvaluator.EvaluateSbomMetadata(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("not applicable", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // --- algorithm ---

    [Fact]
    public void Algorithm_AllAllowed_Passes()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256" },
            new() { KeyId = "k2", IsValid = true, Algorithm = "ecdsa-p384" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256", "ecdsa-p384"] };

        var result = RuleEvaluator.EvaluateAlgorithm(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Algorithm_DisallowedAlgorithm_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "rsa-pss-sha256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] };

        var result = RuleEvaluator.EvaluateAlgorithm(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("rsa-pss-sha256", result.Reason!);
    }

    [Fact]
    public void Algorithm_CaseInsensitive_Passes()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ECDSA-P256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] };

        var result = RuleEvaluator.EvaluateAlgorithm(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Algorithm_InvalidSigsSkipped()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256" },
            new() { KeyId = "k2", IsValid = false, Algorithm = "rsa-pss-sha256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] };

        var result = RuleEvaluator.EvaluateAlgorithm(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Algorithm_NullAlgorithm_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = null }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] };

        var result = RuleEvaluator.EvaluateAlgorithm(rule, context);

        Assert.False(result.Passed);
    }

    // --- label ---

    [Fact]
    public void Label_Matches_Passes()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256", Label = "ci-build" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "label", Match = "ci-*" };

        var result = RuleEvaluator.EvaluateLabel(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Label_NoMatch_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256", Label = "dev-test" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "label", Match = "ci-*" };

        var result = RuleEvaluator.EvaluateLabel(rule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Label_NullLabel_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256", Label = null }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "label", Match = "ci-*" };

        var result = RuleEvaluator.EvaluateLabel(rule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Label_AnyValidSigMatches_Passes()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256", Label = "dev-test" },
            new() { KeyId = "k2", IsValid = true, Algorithm = "ecdsa-p256", Label = "ci-deploy" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "label", Match = "ci-*" };

        var result = RuleEvaluator.EvaluateLabel(rule, context);

        Assert.True(result.Passed);
    }

    // --- key ---

    [Fact]
    public void Key_FingerprintPresent_Passes()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "sha256:abc", IsValid = true, Algorithm = "ecdsa-p256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "key", Fingerprints = ["sha256:abc", "sha256:def"] };

        var result = RuleEvaluator.EvaluateKey(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Key_FingerprintNotPresent_Fails()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "sha256:xyz", IsValid = true, Algorithm = "ecdsa-p256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "key", Fingerprints = ["sha256:abc"] };

        var result = RuleEvaluator.EvaluateKey(rule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Key_InvalidSigNotCounted()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "sha256:abc", IsValid = false, Algorithm = "ecdsa-p256" }
        };
        var context = CreateContext(sigs);
        var rule = new PolicyRule { Require = "key", Fingerprints = ["sha256:abc"] };

        var result = RuleEvaluator.EvaluateKey(rule, context);

        Assert.False(result.Passed);
    }

    // --- trusted ---

    [Fact]
    public void Trusted_NoBasePath_Fails()
    {
        var context = CreateContext(validSigCount: 1);
        var rule = new PolicyRule { Require = "trusted", Bundle = "trust.json" };

        var result = RuleEvaluator.EvaluateTrusted(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("base path", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Trusted_BundleNotFound_Fails()
    {
        var context = new PolicyContext
        {
            Verification = CreateVerification(1),
            BasePath = Path.GetTempPath()
        };
        var rule = new PolicyRule { Require = "trusted", Bundle = "nonexistent-bundle.json" };

        var result = RuleEvaluator.EvaluateTrusted(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("not found", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Trusted_PathTraversal_Rejected()
    {
        var context = new PolicyContext
        {
            Verification = CreateVerification(1),
            BasePath = Path.GetTempPath()
        };
        var rule = new PolicyRule { Require = "trusted", Bundle = "../../../etc/passwd" };

        var result = RuleEvaluator.EvaluateTrusted(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("directory traversal", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Trusted_AbsolutePath_Rejected()
    {
        var context = new PolicyContext
        {
            Verification = CreateVerification(1),
            BasePath = Path.GetTempPath()
        };
        var absolutePath = OperatingSystem.IsWindows()
            ? "C:\\Windows\\System32\\config"
            : "/etc/passwd";
        var rule = new PolicyRule { Require = "trusted", Bundle = absolutePath };

        var result = RuleEvaluator.EvaluateTrusted(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("relative", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // --- RuleName set correctly ---

    [Fact]
    public void AllRules_SetRuleName()
    {
        var context = CreateContext(validSigCount: 1);

        Assert.Equal("min-signatures",
            RuleEvaluator.EvaluateMinSignatures(
                new PolicyRule { Require = "min-signatures", Count = 1 }, context).RuleName);
        Assert.Equal("timestamp",
            RuleEvaluator.EvaluateTimestamp(
                new PolicyRule { Require = "timestamp" }, context).RuleName);
        Assert.Equal("algorithm",
            RuleEvaluator.EvaluateAlgorithm(
                new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] }, context).RuleName);
        Assert.Equal("label",
            RuleEvaluator.EvaluateLabel(
                new PolicyRule { Require = "label", Match = "ci-*" }, context).RuleName);
        Assert.Equal("key",
            RuleEvaluator.EvaluateKey(
                new PolicyRule { Require = "key", Fingerprints = ["sha256:abc"] }, context).RuleName);
        Assert.Equal("trusted",
            RuleEvaluator.EvaluateTrusted(
                new PolicyRule { Require = "trusted", Bundle = "x.json" }, context).RuleName);
        Assert.Equal("sbom-metadata",
            RuleEvaluator.EvaluateSbomMetadata(
                new PolicyRule { Require = "sbom-metadata" }, context).RuleName);
    }

    // --- helpers ---

    private static PolicyContext CreateContext(int validSigCount, SignatureEnvelope? envelope = null)
    {
        return CreateContext(CreateValidSigs(validSigCount), envelope);
    }

    private static PolicyContext CreateContext(
        List<SignatureVerificationResult> sigs,
        SignatureEnvelope? envelope = null)
    {
        return new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures = sigs
            },
            Envelope = envelope
        };
    }

    private static VerificationResult CreateVerification(int validSigCount)
    {
        return new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures = CreateValidSigs(validSigCount)
        };
    }

    private static List<SignatureVerificationResult> CreateValidSigs(int count)
    {
        return Enumerable.Range(1, count)
            .Select(i => new SignatureVerificationResult
            {
                KeyId = $"sha256:key{i}",
                IsValid = true,
                Algorithm = "ecdsa-p256"
            })
            .ToList();
    }
}
