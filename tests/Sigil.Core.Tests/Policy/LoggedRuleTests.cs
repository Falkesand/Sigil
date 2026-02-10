using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Policy;

public class LoggedRuleTests
{
    private static readonly PolicyRule LoggedRule = new() { Require = "logged" };

    [Fact]
    public void Logged_with_transparency_data_passes()
    {
        var context = CreateContextWithTransparency();

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.True(result.Passed);
        Assert.Contains("transparency log receipts", result.Reason);
    }

    [Fact]
    public void Logged_without_transparency_data_fails()
    {
        var context = CreateContextWithoutTransparency();

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Logged_no_envelope_fails()
    {
        var context = new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures =
                [
                    new SignatureVerificationResult
                    {
                        KeyId = "sha256:key1",
                        IsValid = true,
                        Algorithm = "ecdsa-p256"
                    }
                ]
            }
        };

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Logged_only_invalid_signatures_fails()
    {
        var entry = CreateEntryWithTransparency("sha256:key1");
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.txt",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures = [entry]
        };

        var context = new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures =
                [
                    new SignatureVerificationResult
                    {
                        KeyId = "sha256:key1",
                        IsValid = false,
                        Algorithm = "ecdsa-p256"
                    }
                ]
            },
            Envelope = envelope
        };

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Logged_missing_inclusion_proof_fails()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:key1",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-10T12:00:00Z",
            TransparencyLogUrl = "https://log.example.com",
            TransparencySignedCheckpoint = "cp",
            TransparencyInclusionProof = null // Missing!
        };

        var context = CreateContextWithEntry(entry);

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Logged_missing_checkpoint_fails()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:key1",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-10T12:00:00Z",
            TransparencyLogUrl = "https://log.example.com",
            TransparencySignedCheckpoint = null, // Missing!
            TransparencyInclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 0, TreeSize = 1, RootHash = "aa", Hashes = []
            }
        };

        var context = CreateContextWithEntry(entry);

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void Logged_with_valid_logPublicKey_passes()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var publicKeyBase64 = Convert.ToBase64String(publicKey);

        var payload = JsonSerializer.Serialize(new { treeSize = 10, rootHash = "aabb" });
        var canonical = new JsonCanonicalizer(payload).GetEncodedUTF8();
        var signature = ecdsa.SignData(canonical, HashAlgorithmName.SHA256);
        var checkpoint = payload + "." + Convert.ToBase64String(signature);
        var checkpointBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(checkpoint));

        var entry = new SignatureEntry
        {
            KeyId = "sha256:key1",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-10T12:00:00Z",
            TransparencyLogUrl = "https://log.example.com",
            TransparencyLogIndex = 5,
            TransparencySignedCheckpoint = checkpointBase64,
            TransparencyInclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 5, TreeSize = 10, RootHash = "aa", Hashes = []
            }
        };

        var context = CreateContextWithEntry(entry);

        var rule = new PolicyRule { Require = "logged", LogPublicKey = publicKeyBase64 };
        var result = RuleEvaluator.EvaluateLogged(rule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void Logged_with_invalid_logPublicKey_fails()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongPublicKeyBase64 = Convert.ToBase64String(wrongKey.ExportSubjectPublicKeyInfo());

        var payload = JsonSerializer.Serialize(new { treeSize = 10, rootHash = "aabb" });
        var canonical = new JsonCanonicalizer(payload).GetEncodedUTF8();
        var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256);
        var checkpoint = payload + "." + Convert.ToBase64String(signature);
        var checkpointBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(checkpoint));

        var entry = new SignatureEntry
        {
            KeyId = "sha256:key1",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-10T12:00:00Z",
            TransparencyLogUrl = "https://log.example.com",
            TransparencyLogIndex = 5,
            TransparencySignedCheckpoint = checkpointBase64,
            TransparencyInclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 5, TreeSize = 10, RootHash = "aa", Hashes = []
            }
        };

        var context = CreateContextWithEntry(entry);

        var rule = new PolicyRule { Require = "logged", LogPublicKey = wrongPublicKeyBase64 };
        var result = RuleEvaluator.EvaluateLogged(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("checkpoint verification failed", result.Reason);
    }

    [Fact]
    public void Logged_with_bad_base64_logPublicKey_fails()
    {
        var entry = CreateEntryWithTransparency("sha256:key1");
        var context = CreateContextWithEntry(entry);

        var rule = new PolicyRule { Require = "logged", LogPublicKey = "not-valid-base64!!!" };
        var result = RuleEvaluator.EvaluateLogged(rule, context);

        Assert.False(result.Passed);
        Assert.Contains("not valid base64", result.Reason);
    }

    [Fact]
    public void Logged_works_with_manifest_envelope()
    {
        var entry = CreateEntryWithTransparency("sha256:key1");
        var manifest = new ManifestEnvelope
        {
            Subjects =
            [
                new SubjectDescriptor
                {
                    Name = "file1.txt",
                    Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
                }
            ],
            Signatures = [entry]
        };

        var context = new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures =
                [
                    new SignatureVerificationResult
                    {
                        KeyId = "sha256:key1",
                        IsValid = true,
                        Algorithm = "ecdsa-p256"
                    }
                ]
            },
            ManifestEnvelope = manifest
        };

        var result = RuleEvaluator.EvaluateLogged(LoggedRule, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PolicyLoader_accepts_logged_rule()
    {
        var json = """
        {
            "version": "1.0",
            "rules": [{ "require": "logged" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value.Rules);
        Assert.Equal("logged", result.Value.Rules[0].Require);
    }

    [Fact]
    public void PolicyLoader_accepts_logged_with_logPublicKey()
    {
        var json = """
        {
            "version": "1.0",
            "rules": [{ "require": "logged", "logPublicKey": "MFkwEwYH..." }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.True(result.IsSuccess);
        Assert.Equal("MFkwEwYH...", result.Value.Rules[0].LogPublicKey);
    }

    [Fact]
    public void PolicyEvaluator_dispatches_logged_rule()
    {
        var context = CreateContextWithTransparency();
        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "logged" }]
        };

        var result = PolicyEvaluator.Evaluate(policy, context);

        Assert.Single(result.Results);
        Assert.True(result.Results[0].Passed);
        Assert.Equal("logged", result.Results[0].RuleName);
    }

    private static SignatureEntry CreateEntryWithTransparency(string keyId) => new()
    {
        KeyId = keyId,
        Algorithm = "ecdsa-p256",
        PublicKey = "AQID",
        Value = "BAUG",
        Timestamp = "2026-02-10T12:00:00Z",
        TransparencyLogUrl = "https://log.example.com",
        TransparencyLogIndex = 42,
        TransparencySignedCheckpoint = "Y2hlY2twb2ludA==",
        TransparencyInclusionProof = new RemoteInclusionProof
        {
            LeafIndex = 42,
            TreeSize = 100,
            RootHash = "aabbccdd",
            Hashes = ["1111"]
        }
    };

    private static PolicyContext CreateContextWithEntry(SignatureEntry entry) => new()
    {
        Verification = new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = entry.KeyId,
                    IsValid = true,
                    Algorithm = entry.Algorithm
                }
            ]
        },
        Envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.txt",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures = [entry]
        }
    };

    private static PolicyContext CreateContextWithTransparency()
    {
        var entry = CreateEntryWithTransparency("sha256:key1");
        return CreateContextWithEntry(entry);
    }

    private static PolicyContext CreateContextWithoutTransparency()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:key1",
            Algorithm = "ecdsa-p256",
            PublicKey = "AQID",
            Value = "BAUG",
            Timestamp = "2026-02-10T12:00:00Z"
        };

        return new PolicyContext
        {
            Verification = new VerificationResult
            {
                ArtifactDigestMatch = true,
                Signatures =
                [
                    new SignatureVerificationResult
                    {
                        KeyId = "sha256:key1",
                        IsValid = true,
                        Algorithm = "ecdsa-p256"
                    }
                ]
            },
            Envelope = new SignatureEnvelope
            {
                Subject = new SubjectDescriptor
                {
                    Name = "test.txt",
                    Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
                },
                Signatures = [entry]
            }
        };
    }
}
