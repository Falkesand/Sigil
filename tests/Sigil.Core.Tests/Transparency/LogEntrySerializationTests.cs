using System.Text.Json;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class LogEntrySerializationTests
{
    [Fact]
    public void Roundtrip_with_all_fields()
    {
        var entry = new LogEntry
        {
            Index = 42,
            Timestamp = "2026-01-15T10:30:00Z",
            KeyId = "sha256:abc123",
            Algorithm = "ecdsa-p256",
            ArtifactName = "mylib.dll",
            ArtifactDigest = "sha256:def456",
            SignatureDigest = "sha256:sig789",
            Label = "release",
            LeafHash = "sha256:leaf000"
        };

        var json = JsonSerializer.Serialize(entry);
        var deserialized = JsonSerializer.Deserialize<LogEntry>(json)!;

        Assert.Equal(entry.Index, deserialized.Index);
        Assert.Equal(entry.Timestamp, deserialized.Timestamp);
        Assert.Equal(entry.KeyId, deserialized.KeyId);
        Assert.Equal(entry.Algorithm, deserialized.Algorithm);
        Assert.Equal(entry.ArtifactName, deserialized.ArtifactName);
        Assert.Equal(entry.ArtifactDigest, deserialized.ArtifactDigest);
        Assert.Equal(entry.SignatureDigest, deserialized.SignatureDigest);
        Assert.Equal(entry.Label, deserialized.Label);
        Assert.Equal(entry.LeafHash, deserialized.LeafHash);
    }

    [Fact]
    public void Null_label_is_omitted_from_json()
    {
        var entry = new LogEntry
        {
            Index = 0,
            Timestamp = "2026-01-15T10:30:00Z",
            KeyId = "sha256:abc",
            Algorithm = "ecdsa-p256",
            ArtifactName = "test.dll",
            ArtifactDigest = "sha256:aaa",
            SignatureDigest = "sha256:bbb",
            Label = null,
            LeafHash = "sha256:ccc"
        };

        var json = JsonSerializer.Serialize(entry);

        Assert.DoesNotContain("label", json);
    }

    [Fact]
    public void Uses_correct_json_property_names()
    {
        var entry = new LogEntry
        {
            Index = 1,
            Timestamp = "2026-01-15T10:30:00Z",
            KeyId = "sha256:key",
            Algorithm = "rsa-pss-sha256",
            ArtifactName = "app.exe",
            ArtifactDigest = "sha256:art",
            SignatureDigest = "sha256:sig",
            Label = "v1",
            LeafHash = "sha256:leaf"
        };

        var json = JsonSerializer.Serialize(entry);

        Assert.Contains("\"index\":", json);
        Assert.Contains("\"timestamp\":", json);
        Assert.Contains("\"keyId\":", json);
        Assert.Contains("\"algorithm\":", json);
        Assert.Contains("\"artifactName\":", json);
        Assert.Contains("\"artifactDigest\":", json);
        Assert.Contains("\"signatureDigest\":", json);
        Assert.Contains("\"label\":", json);
        Assert.Contains("\"leafHash\":", json);
    }

    [Fact]
    public void Deserialize_without_label_field()
    {
        var json = """{"index":0,"timestamp":"2026-01-15T10:30:00Z","keyId":"sha256:k","algorithm":"ecdsa-p256","artifactName":"f.dll","artifactDigest":"sha256:a","signatureDigest":"sha256:s","leafHash":"sha256:l"}""";

        var entry = JsonSerializer.Deserialize<LogEntry>(json)!;

        Assert.Null(entry.Label);
    }
}
