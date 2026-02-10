using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Integration.Tests;

public class ManifestSignVerifyIntegrationTests : IDisposable
{
    private readonly string _tempDir;

    public ManifestSignVerifyIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-manifest-integ-" + Guid.NewGuid().ToString("N")[..8]);
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
    public void RoundTrip_EphemeralKey_SignAndVerify()
    {
        var file1 = CreateFile("src/main.cs", "class Program {}");
        var file2 = CreateFile("src/util.cs", "class Util {}");
        var file3 = CreateFile("README.md", "# Project");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2, file3], signer, fp, "ci-build");
        var json = ManifestSigner.Serialize(envelope);
        var deserialized = ManifestSigner.Deserialize(json);

        var result = ManifestValidator.Verify(_tempDir, deserialized);

        Assert.True(result.AllDigestsMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(3, result.FileResults.Count);
        Assert.Single(result.Signatures);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
        Assert.Equal("ci-build", result.Signatures[0].Label);
    }

    [Fact]
    public void RoundTrip_PersistentKey_SignAndVerify()
    {
        var file = CreateFile("data.bin", "binary data");

        using var signer = ECDsaP256Signer.Generate();
        var pemPath = Path.Combine(_tempDir, "testkey.pem");
        File.WriteAllText(pemPath, signer.ExportPrivateKeyPem());

        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ManifestSigner.Sign(_tempDir, [file], signer, fp, "release");

        // Reload key from PEM and verify fingerprint matches
        using var reloaded = ECDsaP256Signer.FromPem(File.ReadAllText(pemPath));
        var reloadedFp = KeyFingerprint.Compute(reloaded.PublicKey);
        Assert.Equal(fp, reloadedFp);

        // Serialize and verify from deserialized
        var json = ManifestSigner.Serialize(envelope);
        var deserialized = ManifestSigner.Deserialize(json);
        var result = ManifestValidator.Verify(_tempDir, deserialized);

        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void SubdirectoryFiles_RelativePaths()
    {
        var file1 = CreateFile("src/components/Button.tsx", "export const Button = () => {};");
        var file2 = CreateFile("src/utils/format.ts", "export function format() {}");
        var file3 = CreateFile("tests/Button.test.tsx", "test('renders')");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2, file3], signer, fp);

        // All paths should use forward slashes
        Assert.All(envelope.Subjects, s =>
        {
            Assert.DoesNotContain("\\", s.Name);
            Assert.Contains("/", s.Name);
        });

        // Sorted by relative path
        var names = envelope.Subjects.Select(s => s.Name).ToList();
        var sorted = names.OrderBy(n => n, StringComparer.Ordinal).ToList();
        Assert.Equal(sorted, names);

        var result = ManifestValidator.Verify(_tempDir, envelope);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void AppendSignature_BothVerify()
    {
        var file1 = CreateFile("app.dll", "assembly bytes");
        var file2 = CreateFile("app.exe", "executable bytes");

        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        // Sign with first key
        var envelope = ManifestSigner.Sign(_tempDir, [file1, file2], signer1, fp1, "author");

        // Append with second key
        ManifestSigner.AppendSignature(envelope, signer2, fp2, "auditor");
        Assert.Equal(2, envelope.Signatures.Count);

        // Serialize, deserialize, and verify
        var json = ManifestSigner.Serialize(envelope);
        var deserialized = ManifestSigner.Deserialize(json);
        var result = ManifestValidator.Verify(_tempDir, deserialized);

        Assert.True(result.AllDigestsMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(2, result.Signatures.Count);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
        Assert.Equal("ecdsa-p384", result.Signatures[1].Algorithm);
    }

    [Fact]
    public void SingleFile_Works()
    {
        var file = CreateFile("single.txt", "just one file");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ManifestSigner.Sign(_tempDir, [file], signer, fp);

        Assert.Single(envelope.Subjects);
        Assert.Equal("single.txt", envelope.Subjects[0].Name);

        var json = ManifestSigner.Serialize(envelope);
        var deserialized = ManifestSigner.Deserialize(json);
        var result = ManifestValidator.Verify(_tempDir, deserialized);

        Assert.True(result.AllSignaturesValid);
    }
}
