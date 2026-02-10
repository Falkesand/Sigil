using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class ManifestValidatorTests : IDisposable
{
    private readonly string _tempDir;

    public ManifestValidatorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-mv-test-" + Guid.NewGuid().ToString("N")[..8]);
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
    public void Verify_AllFilesMatch_AllSignaturesValid()
    {
        var file1 = CreateFile("a.txt", "aaa");
        var file2 = CreateFile("b.txt", "bbb");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer, fp);

        var result = ManifestValidator.Verify(_tempDir, envelope);

        Assert.True(result.AllDigestsMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(2, result.FileResults.Count);
        Assert.Single(result.Signatures);
    }

    [Fact]
    public void Verify_TamperedFile_DigestMismatch()
    {
        var file1 = CreateFile("good.txt", "original");
        var file2 = CreateFile("tampered.txt", "original");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer, fp);

        // Tamper with file
        File.WriteAllText(file2, "MODIFIED");

        var result = ManifestValidator.Verify(_tempDir, envelope);

        Assert.False(result.AllDigestsMatch);
        Assert.False(result.AllSignaturesValid);

        var goodResult = result.FileResults.First(f => f.Name == "good.txt");
        var badResult = result.FileResults.First(f => f.Name == "tampered.txt");
        Assert.True(goodResult.DigestMatch);
        Assert.False(badResult.DigestMatch);
    }

    [Fact]
    public void Verify_MissingFile_ReportsError()
    {
        var file1 = CreateFile("exists.txt", "here");
        var file2 = CreateFile("missing.txt", "gone");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer, fp);

        // Delete file
        File.Delete(file2);

        var result = ManifestValidator.Verify(_tempDir, envelope);

        Assert.False(result.AllDigestsMatch);
        var missingResult = result.FileResults.First(f => f.Name == "missing.txt");
        Assert.False(missingResult.DigestMatch);
        Assert.Contains("not found", missingResult.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_TamperedSubject_SignatureInvalid()
    {
        var file1 = CreateFile("data.txt", "data");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file1], signer, fp);

        // Tamper with subject name in envelope (rename from data.txt to hacked.txt)
        var tampered = new ManifestEnvelope
        {
            Subjects = [new SubjectDescriptor
            {
                Name = "hacked.txt",
                Digests = envelope.Subjects[0].Digests
            }],
            Signatures = envelope.Signatures
        };

        // Create the renamed file with same content
        CreateFile("hacked.txt", "data");

        var result = ManifestValidator.Verify(_tempDir, tampered);

        // Digests match (same content) but signature should be invalid (subjects array changed)
        Assert.True(result.AllDigestsMatch);
        Assert.False(result.AllSignaturesValid);
    }

    [Fact]
    public void Verify_MultipleSignatures_AllVerified()
    {
        var file = CreateFile("multi.txt", "multi-sig test");

        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file], signer1, fp1);
        ManifestSigner.AppendSignature(envelope, signer2, fp2);

        var result = ManifestValidator.Verify(_tempDir, envelope);

        Assert.True(result.AllDigestsMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(2, result.Signatures.Count);
    }

    [Fact]
    public void Verify_EmptyManifest_ReportsError()
    {
        var envelope = new ManifestEnvelope
        {
            Subjects = []
        };

        var result = ManifestValidator.Verify(_tempDir, envelope);

        Assert.False(result.AllDigestsMatch);
        Assert.Single(result.FileResults);
        Assert.Contains("no subjects", result.FileResults[0].Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ManifestTrustAdapter_MapsCorrectly()
    {
        var file1 = CreateFile("adapt.txt", "adapt");
        var file2 = CreateFile("adapt2.txt", "adapt2");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer, fp);

        var manifestResult = ManifestValidator.Verify(_tempDir, envelope);
        var verificationResult = ManifestTrustAdapter.ToVerificationResult(manifestResult);

        Assert.True(verificationResult.ArtifactDigestMatch);
        Assert.Equal(manifestResult.Signatures.Count, verificationResult.Signatures.Count);
        Assert.True(verificationResult.AllSignaturesValid);
    }

    [Fact]
    public void ManifestTrustAdapter_FailingDigests_MapsToFalse()
    {
        var file = CreateFile("fail.txt", "original");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file], signer, fp);

        // Tamper with file
        File.WriteAllText(file, "TAMPERED");

        var manifestResult = ManifestValidator.Verify(_tempDir, envelope);
        var verificationResult = ManifestTrustAdapter.ToVerificationResult(manifestResult);

        Assert.False(verificationResult.ArtifactDigestMatch);
        Assert.False(verificationResult.AllSignaturesValid);
    }

    [Fact]
    public void Verify_PathTraversal_Rejected()
    {
        var file = CreateFile("legit.txt", "safe");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file], signer, fp);

        // Replace subject with path traversal attempt
        var tampered = new ManifestEnvelope
        {
            Subjects = [new SubjectDescriptor
            {
                Name = "../../../etc/passwd",
                Digests = envelope.Subjects[0].Digests
            }],
            Signatures = envelope.Signatures
        };

        var result = ManifestValidator.Verify(_tempDir, tampered);

        Assert.False(result.AllDigestsMatch);
        var traversalResult = result.FileResults[0];
        Assert.False(traversalResult.DigestMatch);
        Assert.Contains("traversal", traversalResult.Error, StringComparison.OrdinalIgnoreCase);
    }
}
