using System.Text.Json;
using Sigil.Policy;

namespace Sigil.Core.Tests.Policy;

public class PolicyDocumentSerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    [Fact]
    public void Roundtrip_MinSignaturesRule()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "min-signatures", Count = 2 }]
        };

        var json = JsonSerializer.Serialize(doc, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions)!;

        Assert.Equal("1.0", deserialized.Version);
        Assert.Single(deserialized.Rules);
        Assert.Equal("min-signatures", deserialized.Rules[0].Require);
        Assert.Equal(2, deserialized.Rules[0].Count);
    }

    [Fact]
    public void Roundtrip_AllRuleTypes()
    {
        var doc = new PolicyDocument
        {
            Rules =
            [
                new PolicyRule { Require = "min-signatures", Count = 2 },
                new PolicyRule { Require = "timestamp" },
                new PolicyRule { Require = "sbom-metadata" },
                new PolicyRule { Require = "algorithm", Allowed = ["ecdsa-p256", "ecdsa-p384"] },
                new PolicyRule { Require = "label", Match = "ci-*" },
                new PolicyRule { Require = "trusted", Bundle = "trust.json", Authority = "sha256:abc" },
                new PolicyRule { Require = "key", Fingerprints = ["sha256:abc", "sha256:def"] }
            ]
        };

        var json = JsonSerializer.Serialize(doc, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions)!;

        Assert.Equal(7, deserialized.Rules.Count);
    }

    [Fact]
    public void Version_DefaultsTo1_0()
    {
        var doc = new PolicyDocument();

        Assert.Equal("1.0", doc.Version);
    }

    [Fact]
    public void NullFields_OmittedInJson()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "timestamp" }]
        };

        var json = JsonSerializer.Serialize(doc, JsonOptions);

        Assert.DoesNotContain("count", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("allowed", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("match", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("bundle", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fingerprints", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Deserialize_FromJsonString()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [
            { "require": "min-signatures", "count": 3 },
            { "require": "algorithm", "allowed": ["rsa-pss-sha256"] }
          ]
        }
        """;

        var doc = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions)!;

        Assert.Equal(2, doc.Rules.Count);
        Assert.Equal(3, doc.Rules[0].Count);
        Assert.Single(doc.Rules[1].Allowed!);
        Assert.Equal("rsa-pss-sha256", doc.Rules[1].Allowed![0]);
    }

    [Fact]
    public void TrustedRule_AuthorityIsOptional()
    {
        var doc = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "trusted", Bundle = "trust.json" }]
        };

        var json = JsonSerializer.Serialize(doc, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions)!;

        Assert.Null(deserialized.Rules[0].Authority);
        Assert.Equal("trust.json", deserialized.Rules[0].Bundle);
    }
}
