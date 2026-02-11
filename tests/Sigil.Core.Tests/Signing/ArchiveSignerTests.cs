using System.Formats.Tar;
using System.IO.Compression;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class ArchiveSignerTests : IDisposable
{
    private readonly string _tempDir;

    public ArchiveSignerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-archsign-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Sign_Zip_ProducesValidEnvelope()
    {
        var path = CreateZipArchive("test.zip",
            ("a.txt", "aaa"),
            ("b.txt", "bbb"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        Assert.Equal("1.0", envelope.Version);
        Assert.Equal("archive", envelope.Kind);
        Assert.Equal(2, envelope.Subjects.Count);
        Assert.Single(envelope.Signatures);
        Assert.Equal(fp.Value, envelope.Signatures[0].KeyId);
    }

    [Fact]
    public void Sign_TarGz_ProducesValidEnvelope()
    {
        var path = CreateTarGzArchive("test.tar.gz",
            ("x.txt", "xxx"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.TarGz, signer, fp);

        Assert.Equal("archive", envelope.Kind);
        Assert.Single(envelope.Subjects);
        Assert.Equal("x.txt", envelope.Subjects[0].Name);
    }

    [Fact]
    public void Sign_SubjectsHaveCorrectDigests()
    {
        var content = "known content for digest"u8.ToArray();
        var path = CreateZipArchiveFromBytes("digest.zip",
            ("data.bin", content));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        var subject = envelope.Subjects[0];
        Assert.Equal("data.bin", subject.Name);
        Assert.True(subject.Digests.ContainsKey("sha256"));
        Assert.True(subject.Digests.ContainsKey("sha512"));

        // Verify digests match
        var (expectedSha256, expectedSha512) = HashAlgorithms.ComputeDigests(content);
        Assert.Equal(expectedSha256, subject.Digests["sha256"]);
        Assert.Equal(expectedSha512, subject.Digests["sha512"]);
    }

    [Fact]
    public void Sign_SubjectsSortedByPath()
    {
        var path = CreateZipArchive("sorted.zip",
            ("c.txt", "ccc"),
            ("a.txt", "aaa"),
            ("b.txt", "bbb"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        Assert.Equal("a.txt", envelope.Subjects[0].Name);
        Assert.Equal("b.txt", envelope.Subjects[1].Name);
        Assert.Equal("c.txt", envelope.Subjects[2].Name);
    }

    [Fact]
    public void Sign_WithLabel_SetsLabel()
    {
        var path = CreateZipArchive("label.zip", ("f.txt", "data"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp, label: "release-v1");

        Assert.Equal("release-v1", envelope.Signatures[0].Label);
    }

    [Fact]
    public void Sign_DetectsSbomEntry()
    {
        var cdx = """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }
        """;
        var path = CreateZipArchive("sbom.zip",
            ("sbom.cdx.json", cdx),
            ("code.cs", "class C {}"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // The SBOM entry should have metadata
        var sbomSubject = envelope.Subjects.First(s => s.Name == "sbom.cdx.json");
        Assert.NotNull(sbomSubject.Metadata);
        Assert.Equal("CycloneDX", sbomSubject.Metadata!["sbom.format"]);
        Assert.Equal("application/vnd.cyclonedx+json", sbomSubject.MediaType);

        // The code entry should not
        var codeSubject = envelope.Subjects.First(s => s.Name == "code.cs");
        Assert.Null(codeSubject.Metadata);
    }

    [Fact]
    public void AppendSignature_AddsSecondSignature()
    {
        var path = CreateZipArchive("multi.zip", ("data.txt", "content"));

        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer1, fp1, label: "author");
        ArchiveSigner.AppendSignature(envelope, signer2, fp2, "reviewer");

        Assert.Equal(2, envelope.Signatures.Count);
        Assert.Equal("author", envelope.Signatures[0].Label);
        Assert.Equal("reviewer", envelope.Signatures[1].Label);
        Assert.NotEqual(envelope.Signatures[0].KeyId, envelope.Signatures[1].KeyId);
    }

    [Fact]
    public void Sign_Nupkg_AttachesNuGetMetadata()
    {
        var nuspec = """
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
          <metadata>
            <id>TestPkg</id>
            <version>1.0.0</version>
            <authors>Author</authors>
          </metadata>
        </package>
        """;
        var path = Path.Combine(_tempDir, "TestPkg.1.0.0.nupkg");
        using (var fs = File.Create(path))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            var nuspecEntry = zip.CreateEntry("TestPkg.nuspec");
            using (var writer = new StreamWriter(nuspecEntry.Open()))
            {
                writer.Write(nuspec);
            }

            var libEntry = zip.CreateEntry("lib/net10.0/TestPkg.dll");
            using (var libWriter = new StreamWriter(libEntry.Open()))
            {
                libWriter.Write("binary data");
            }
        }

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // All subjects should have NuGet metadata
        Assert.All(envelope.Subjects, s =>
        {
            Assert.NotNull(s.Metadata);
            Assert.Equal("TestPkg", s.Metadata!["nuget.id"]);
            Assert.Equal("1.0.0", s.Metadata["nuget.version"]);
        });
    }

    [Fact]
    public async Task SignAsync_ProducesValidEnvelope()
    {
        var path = CreateZipArchive("async.zip", ("f.txt", "async content"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = await ArchiveSigner.SignAsync(path, ArchiveFormat.Zip, signer, fp, label: "async");

        Assert.Equal("archive", envelope.Kind);
        Assert.Single(envelope.Signatures);
        Assert.Equal("async", envelope.Signatures[0].Label);
    }

    [Fact]
    public void Serialize_Deserialize_RoundTrip()
    {
        var path = CreateZipArchive("rt.zip",
            ("r.txt", "round"),
            ("t.txt", "trip"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp, label: "roundtrip");
        var json = ArchiveSigner.Serialize(envelope);
        var deserialized = ArchiveSigner.Deserialize(json);

        Assert.Equal(envelope.Version, deserialized.Version);
        Assert.Equal(envelope.Kind, deserialized.Kind);
        Assert.Equal(envelope.Subjects.Count, deserialized.Subjects.Count);
        Assert.Equal(envelope.Subjects[0].Name, deserialized.Subjects[0].Name);
        Assert.Equal(envelope.Subjects[0].Digests["sha256"], deserialized.Subjects[0].Digests["sha256"]);
        Assert.Equal(envelope.Signatures[0].KeyId, deserialized.Signatures[0].KeyId);
        Assert.Equal(envelope.Signatures[0].Value, deserialized.Signatures[0].Value);
    }

    [Fact]
    public void BuildSubjects_EmptyArchive_ThrowsArgumentException()
    {
        // Create a ZIP with no file entries (only a directory)
        var path = Path.Combine(_tempDir, "empty.zip");
        using (var fs = File.Create(path))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            zip.CreateEntry("empty-dir/");
        }

        Assert.Throws<ArgumentException>(
            () => ArchiveSigner.BuildSubjects(path, ArchiveFormat.Zip));
    }

    [Fact]
    public void Sign_UsesManifestSignerPayload()
    {
        // Verify the signing payload matches ManifestSigner.BuildManifestSigningPayload
        var path = CreateZipArchive("payload.zip", ("p.txt", "payload test"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // Rebuild the payload and verify the signature
        var sig = envelope.Signatures[0];
        var payload = ManifestSigner.BuildManifestSigningPayload(
            envelope.Subjects, envelope.Version, sig.KeyId, sig.Algorithm, sig.Timestamp, sig.Label);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            Convert.FromBase64String(sig.PublicKey), sig.Algorithm);
        var isValid = verifier.Verify(payload, Convert.FromBase64String(sig.Value));

        Assert.True(isValid);
    }

    // --- Helpers ---

    private string CreateZipArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        foreach (var (entryName, content) in entries)
        {
            var entry = zip.CreateEntry(entryName);
            using var writer = new StreamWriter(entry.Open());
            writer.Write(content);
        }
        return path;
    }

    private string CreateZipArchiveFromBytes(string name, params (string entryName, byte[] content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        foreach (var (entryName, content) in entries)
        {
            var entry = zip.CreateEntry(entryName);
            using var stream = entry.Open();
            stream.Write(content);
        }
        return path;
    }

    private string CreateTarGzArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Optimal);
        using var tar = new TarWriter(gz, TarEntryFormat.Pax);
        foreach (var (entryName, content) in entries)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(content);
            var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(bytes)
            };
            tar.WriteEntry(entry);
        }
        return path;
    }
}
