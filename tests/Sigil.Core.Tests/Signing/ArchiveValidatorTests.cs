using System.IO.Compression;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class ArchiveValidatorTests : IDisposable
{
    private readonly string _tempDir;

    public ArchiveValidatorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-archval-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Verify_ValidArchive_AllDigestsMatch()
    {
        var path = CreateZipArchive("valid.zip",
            ("a.txt", "aaa"),
            ("b.txt", "bbb"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        var result = ArchiveValidator.Verify(path, envelope);

        Assert.True(result.AllDigestsMatch);
        Assert.Equal(2, result.Entries.Count);
        Assert.All(result.Entries, e => Assert.True(e.DigestMatch));
        Assert.Empty(result.ExtraEntries);
    }

    [Fact]
    public void Verify_ValidArchive_AllSignaturesValid()
    {
        var path = CreateZipArchive("sigvalid.zip", ("f.txt", "content"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        var result = ArchiveValidator.Verify(path, envelope);

        Assert.Single(result.Signatures);
        Assert.True(result.Signatures[0].IsValid);
    }

    [Fact]
    public void Verify_TamperedEntry_DetectsDigestMismatch()
    {
        var path = CreateZipArchive("tamper.zip",
            ("data.txt", "original"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // Tamper: recreate the archive with different content
        var tamperedPath = CreateZipArchive("tamper.zip",
            ("data.txt", "TAMPERED"));

        var result = ArchiveValidator.Verify(tamperedPath, envelope);

        Assert.False(result.AllDigestsMatch);
        Assert.Contains(result.Entries, e => !e.DigestMatch && e.Name == "data.txt");
    }

    [Fact]
    public void Verify_MissingEntry_DetectedAsError()
    {
        var path = CreateZipArchive("missing.zip",
            ("keep.txt", "keep"),
            ("remove.txt", "gone"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // Recreate archive without one file
        var newPath = CreateZipArchive("missing.zip",
            ("keep.txt", "keep"));

        var result = ArchiveValidator.Verify(newPath, envelope);

        Assert.False(result.AllDigestsMatch);
        var missingEntry = result.Entries.First(e => e.Name == "remove.txt");
        Assert.False(missingEntry.DigestMatch);
        Assert.Contains("not found", missingEntry.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_ExtraEntry_ReportedAsExtra()
    {
        var path = CreateZipArchive("extra.zip",
            ("original.txt", "orig"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // Recreate with an additional file
        var newPath = CreateZipArchive("extra.zip",
            ("original.txt", "orig"),
            ("bonus.txt", "extra!"));

        var result = ArchiveValidator.Verify(newPath, envelope);

        Assert.True(result.AllDigestsMatch);
        Assert.Contains("bonus.txt", result.ExtraEntries);
    }

    [Fact]
    public void Verify_InvalidSignature_DetectedAsInvalid()
    {
        var path = CreateZipArchive("badsig.zip", ("f.txt", "data"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        // Corrupt the signature value
        var corruptedSig = envelope.Signatures[0];
        var corruptedBytes = Convert.FromBase64String(corruptedSig.Value);
        corruptedBytes[0] ^= 0xFF;
        envelope.Signatures[0] = new SignatureEntry
        {
            KeyId = corruptedSig.KeyId,
            Algorithm = corruptedSig.Algorithm,
            PublicKey = corruptedSig.PublicKey,
            Value = Convert.ToBase64String(corruptedBytes),
            Timestamp = corruptedSig.Timestamp,
            Label = corruptedSig.Label
        };

        var result = ArchiveValidator.Verify(path, envelope);

        Assert.True(result.AllDigestsMatch);
        Assert.Single(result.Signatures);
        Assert.False(result.Signatures[0].IsValid);
    }

    [Fact]
    public void Verify_MultipleSignatures_AllValidated()
    {
        var path = CreateZipArchive("multi.zip", ("m.txt", "multi"));

        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer1, fp1, label: "first");
        ArchiveSigner.AppendSignature(envelope, signer2, fp2, "second");

        var result = ArchiveValidator.Verify(path, envelope);

        Assert.Equal(2, result.Signatures.Count);
        Assert.True(result.Signatures[0].IsValid);
        Assert.True(result.Signatures[1].IsValid);
    }

    [Fact]
    public void Verify_EmptySubjects_ReportsError()
    {
        var path = CreateZipArchive("empty-env.zip", ("f.txt", "content"));

        var envelope = new ManifestEnvelope
        {
            Kind = "archive",
            Subjects = []
        };

        var result = ArchiveValidator.Verify(path, envelope);

        Assert.False(result.AllDigestsMatch);
    }

    [Fact]
    public void Verify_TarGz_ValidArchive_Passes()
    {
        var path = CreateTarGzArchive("valid.tar.gz",
            ("x.txt", "xxx"),
            ("y.txt", "yyy"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.TarGz, signer, fp);

        var result = ArchiveValidator.Verify(path, envelope);

        Assert.True(result.AllDigestsMatch);
        Assert.True(result.Signatures[0].IsValid);
    }

    [Fact]
    public void ToVerificationResult_MapsCorrectly()
    {
        var path = CreateZipArchive("adapter.zip", ("a.txt", "content"));

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArchiveSigner.Sign(path, ArchiveFormat.Zip, signer, fp);

        var archiveResult = ArchiveValidator.Verify(path, envelope);
        var verification = ArchiveValidator.ToVerificationResult(archiveResult);

        Assert.True(verification.ArtifactDigestMatch);
        Assert.Single(verification.Signatures);
        Assert.True(verification.AllSignaturesValid);
    }

    // --- Helpers ---

    private string CreateZipArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        // Delete if exists (for tamper tests)
        if (File.Exists(path))
            File.Delete(path);
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

    private string CreateTarGzArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Optimal);
        using var tar = new System.Formats.Tar.TarWriter(gz, System.Formats.Tar.TarEntryFormat.Pax);
        foreach (var (entryName, content) in entries)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(content);
            var entry = new System.Formats.Tar.PaxTarEntry(
                System.Formats.Tar.TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(bytes)
            };
            tar.WriteEntry(entry);
        }
        return path;
    }
}
