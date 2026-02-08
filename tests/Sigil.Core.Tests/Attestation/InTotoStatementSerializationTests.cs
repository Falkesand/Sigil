using System.Text.Json;
using Sigil.Attestation;

namespace Sigil.Core.Tests.Attestation;

public class InTotoStatementSerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void Roundtrip_preserves_all_fields()
    {
        var predicate = JsonSerializer.SerializeToElement(new { builder = "ci", buildType = "github" });

        var statement = new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = "release.tar.gz",
                    Digest = new Dictionary<string, string> { ["sha256"] = "abc123" }
                }
            ],
            PredicateType = "https://slsa.dev/provenance/v1",
            Predicate = predicate
        };

        var json = JsonSerializer.Serialize(statement, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<InTotoStatement>(json, JsonOptions)!;

        Assert.Equal(statement.Type, deserialized.Type);
        Assert.Equal(statement.PredicateType, deserialized.PredicateType);
        Assert.Single(deserialized.Subject);
        Assert.Equal("release.tar.gz", deserialized.Subject[0].Name);
        Assert.Equal("abc123", deserialized.Subject[0].Digest["sha256"]);
    }

    [Fact]
    public void Default_type_is_intoto_v1()
    {
        var statement = new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = "test",
                    Digest = new Dictionary<string, string> { ["sha256"] = "000" }
                }
            ],
            PredicateType = "https://example.com/pred"
        };

        Assert.Equal("https://in-toto.io/Statement/v1", statement.Type);
    }

    [Fact]
    public void Null_predicate_omitted_in_json()
    {
        var statement = new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = "test",
                    Digest = new Dictionary<string, string> { ["sha256"] = "abc" }
                }
            ],
            PredicateType = "https://example.com/pred"
        };

        var json = JsonSerializer.Serialize(statement, JsonOptions);

        Assert.DoesNotContain("\"predicate\"", json);
    }

    [Fact]
    public void Multiple_subjects_roundtrip()
    {
        var statement = new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = "file-a.tar.gz",
                    Digest = new Dictionary<string, string> { ["sha256"] = "aaa" }
                },
                new InTotoSubject
                {
                    Name = "file-b.tar.gz",
                    Digest = new Dictionary<string, string> { ["sha256"] = "bbb", ["sha512"] = "ccc" }
                }
            ],
            PredicateType = "https://slsa.dev/provenance/v1"
        };

        var json = JsonSerializer.Serialize(statement, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<InTotoStatement>(json, JsonOptions)!;

        Assert.Equal(2, deserialized.Subject.Count);
        Assert.Equal("file-b.tar.gz", deserialized.Subject[1].Name);
        Assert.Equal("ccc", deserialized.Subject[1].Digest["sha512"]);
    }

    [Fact]
    public void Type_field_serializes_as_underscore_type()
    {
        var statement = new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = "test",
                    Digest = new Dictionary<string, string> { ["sha256"] = "abc" }
                }
            ],
            PredicateType = "https://example.com/pred"
        };

        var json = JsonSerializer.Serialize(statement, JsonOptions);

        Assert.Contains("\"_type\"", json);
        Assert.DoesNotContain("\"Type\"", json);
    }
}
