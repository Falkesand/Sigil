using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class ManifestSignerTests : IDisposable
{
    private readonly string _tempDir;

    public ManifestSignerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-manifest-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private string CreateFile(string relativePath, string content)
    {
        var fullPath = Path.Combine(_tempDir, relativePath.Replace('/', Path.DirectorySeparatorChar));
        var dir = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(fullPath, content);
        return fullPath;
    }

    [Fact]
    public void BuildSubjects_CreatesSubjectPerFile()
    {
        var file1 = CreateFile("main.cs", "class Main {}");
        var file2 = CreateFile("util.cs", "class Util {}");
        var file3 = CreateFile("config.json", "{}");

        var subjects = ManifestSigner.BuildSubjects(_tempDir, [file1, file2, file3]);

        Assert.Equal(3, subjects.Count);
        foreach (var subject in subjects)
        {
            Assert.True(subject.Digests.ContainsKey("sha256"));
            Assert.True(subject.Digests.ContainsKey("sha512"));
        }
    }

    [Fact]
    public void BuildSubjects_UsesForwardSlashPaths()
    {
        var subDir = Path.Combine(_tempDir, "src");
        Directory.CreateDirectory(subDir);
        var file = CreateFile("src/file.txt", "hello");

        var subjects = ManifestSigner.BuildSubjects(_tempDir, [file]);

        Assert.Single(subjects);
        Assert.Equal("src/file.txt", subjects[0].Name);
        Assert.DoesNotContain("\\", subjects[0].Name);
    }

    [Fact]
    public void BuildSubjects_DetectsSbomMetadata()
    {
        var cdx = """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }
        """;
        var file = CreateFile("sbom.cdx.json", cdx);

        var subjects = ManifestSigner.BuildSubjects(_tempDir, [file]);

        Assert.Single(subjects);
        Assert.NotNull(subjects[0].Metadata);
        Assert.Equal("CycloneDX", subjects[0].Metadata!["sbom.format"]);
        Assert.Equal("application/vnd.cyclonedx+json", subjects[0].MediaType);
    }

    [Fact]
    public void Sign_ProducesValidEnvelope()
    {
        var file1 = CreateFile("a.txt", "aaa");
        var file2 = CreateFile("b.txt", "bbb");
        var file3 = CreateFile("c.txt", "ccc");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2, file3], signer, fp, "test");

        Assert.Equal("1.0", envelope.Version);
        Assert.Equal("manifest", envelope.Kind);
        Assert.Equal(3, envelope.Subjects.Count);
        Assert.Single(envelope.Signatures);
        Assert.Equal(fp.Value, envelope.Signatures[0].KeyId);
        Assert.Equal("ecdsa-p256", envelope.Signatures[0].Algorithm);
        Assert.Equal("test", envelope.Signatures[0].Label);
    }

    [Fact]
    public void Serialize_Deserialize_RoundTrip()
    {
        var file1 = CreateFile("x.txt", "xxx");
        var file2 = CreateFile("y.txt", "yyy");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer, fp, "roundtrip");
        var json = ManifestSigner.Serialize(envelope);
        var deserialized = ManifestSigner.Deserialize(json);

        Assert.Equal(envelope.Version, deserialized.Version);
        Assert.Equal(envelope.Kind, deserialized.Kind);
        Assert.Equal(envelope.Subjects.Count, deserialized.Subjects.Count);
        Assert.Equal(envelope.Subjects[0].Name, deserialized.Subjects[0].Name);
        Assert.Equal(envelope.Subjects[0].Digests["sha256"], deserialized.Subjects[0].Digests["sha256"]);
        Assert.Equal(envelope.Signatures[0].KeyId, deserialized.Signatures[0].KeyId);
        Assert.Equal(envelope.Signatures[0].Value, deserialized.Signatures[0].Value);
        Assert.Equal(envelope.Signatures[0].Label, deserialized.Signatures[0].Label);
    }

    [Fact]
    public void BuildManifestSigningPayload_IsDeterministic()
    {
        var file1 = CreateFile("d1.txt", "deterministic");
        var file2 = CreateFile("d2.txt", "test");

        var subjects = ManifestSigner.BuildSubjects(_tempDir, [file1, file2]);

        var payload1 = ManifestSigner.BuildManifestSigningPayload(
            subjects, "1.0", "sha256:abc", "ecdsa-p256", "2025-01-01T00:00:00Z", null);
        var payload2 = ManifestSigner.BuildManifestSigningPayload(
            subjects, "1.0", "sha256:abc", "ecdsa-p256", "2025-01-01T00:00:00Z", null);

        Assert.Equal(payload1, payload2);
    }

    [Fact]
    public void AppendSignature_AddsSecondSignature()
    {
        var file = CreateFile("single.txt", "content");

        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file], signer1, fp1, "author");
        ManifestSigner.AppendSignature(envelope, signer2, fp2, "auditor");

        Assert.Equal(2, envelope.Signatures.Count);
        Assert.Equal("author", envelope.Signatures[0].Label);
        Assert.Equal("auditor", envelope.Signatures[1].Label);
        Assert.NotEqual(envelope.Signatures[0].KeyId, envelope.Signatures[1].KeyId);
    }
}
