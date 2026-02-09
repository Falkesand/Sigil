using Sigil.Policy;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Core.Tests.Policy;

public class PolicyEvaluatorTests
{
    [Fact]
    public void Evaluate_SinglePassingRule_AllPassed()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "min-signatures", Count = 1 }]
        };
        var context = CreateContext(validSigCount: 1);

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.True(result.AllPassed);
        Assert.False(result.AnyFailed);
        Assert.Single(result.Results);
    }

    [Fact]
    public void Evaluate_SingleFailingRule_AnyFailed()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "min-signatures", Count = 3 }]
        };
        var context = CreateContext(validSigCount: 1);

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.False(result.AllPassed);
        Assert.True(result.AnyFailed);
    }

    [Fact]
    public void Evaluate_MixedResults_NotAllPassed()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new() { KeyId = "sha256:k1", IsValid = true, Algorithm = "ecdsa-p256" }
        };
        var doc = new PolicyDocument
        {
            Rules =
            [
                new PolicyRule { Require = "min-signatures", Count = 1 },
                new PolicyRule { Require = "timestamp" }
            ]
        };
        var context = new PolicyContext
        {
            Verification = new VerificationResult { ArtifactDigestMatch = true, Signatures = sigs }
        };

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.False(result.AllPassed);
        Assert.True(result.AnyFailed);
        Assert.Equal(2, result.Results.Count);
        Assert.True(result.Results[0].Passed);
        Assert.False(result.Results[1].Passed);
    }

    [Fact]
    public void Evaluate_AllRulesPass()
    {
        var sigs = new List<SignatureVerificationResult>
        {
            new()
            {
                KeyId = "sha256:abc", IsValid = true, Algorithm = "ecdsa-p256",
                Label = "ci-build",
                TimestampInfo = new TimestampVerificationInfo { IsValid = true, Timestamp = DateTimeOffset.UtcNow }
            }
        };
        var doc = new PolicyDocument
        {
            Rules =
            [
                new PolicyRule { Require = "min-signatures", Count = 1 },
                new PolicyRule { Require = "timestamp" },
                new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] },
                new PolicyRule { Require = "label", Match = "ci-*" },
                new PolicyRule { Require = "key", Fingerprints = ["sha256:abc"] }
            ]
        };
        var context = new PolicyContext
        {
            Verification = new VerificationResult { ArtifactDigestMatch = true, Signatures = sigs }
        };

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.True(result.AllPassed);
        Assert.Equal(5, result.Results.Count);
    }

    [Fact]
    public void Evaluate_NoShortCircuit_AllRulesEvaluated()
    {
        var doc = new PolicyDocument
        {
            Rules =
            [
                new PolicyRule { Require = "min-signatures", Count = 10 },
                new PolicyRule { Require = "timestamp" },
                new PolicyRule { Require = "algorithm", Allowed = ["ed25519"] }
            ]
        };
        var context = CreateContext(validSigCount: 1);

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.Equal(3, result.Results.Count);
        Assert.True(result.Results.All(r => !r.Passed));
    }

    [Fact]
    public void Evaluate_UnknownRuleType_FailsGracefully()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "unknown-rule" }]
        };
        var context = CreateContext(validSigCount: 1);

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.Single(result.Results);
        Assert.False(result.Results[0].Passed);
        Assert.Contains("Unknown rule type", result.Results[0].Reason!);
    }

    [Fact]
    public void Evaluate_ResultsInOrder()
    {
        var doc = new PolicyDocument
        {
            Rules =
            [
                new PolicyRule { Require = "min-signatures", Count = 1 },
                new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256"] },
                new PolicyRule { Require = "key", Fingerprints = ["sha256:key1"] }
            ]
        };
        var context = CreateContext(validSigCount: 1);

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.Equal("min-signatures", result.Results[0].RuleName);
        Assert.Equal("algorithm", result.Results[1].RuleName);
        Assert.Equal("key", result.Results[2].RuleName);
    }

    [Fact]
    public void Evaluate_EmptySignatures_MinSignaturesFails()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "min-signatures", Count = 1 }]
        };
        var context = new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures = []
            }
        };

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.False(result.AllPassed);
    }

    [Fact]
    public void Evaluate_SbomMetadataWithEnvelope_Passes()
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
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "sbom-metadata" }]
        };
        var context = new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures = [new SignatureVerificationResult { KeyId = "k1", IsValid = true, Algorithm = "ecdsa-p256" }]
            },
            Envelope = envelope
        };

        var result = PolicyEvaluator.Evaluate(doc, context);

        Assert.True(result.AllPassed);
    }

    private static PolicyContext CreateContext(int validSigCount)
    {
        var sigs = Enumerable.Range(1, validSigCount)
            .Select(i => new SignatureVerificationResult
            {
                KeyId = $"sha256:key{i}",
                IsValid = true,
                Algorithm = "ecdsa-p256"
            })
            .ToList();

        return new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures = sigs
            }
        };
    }
}
