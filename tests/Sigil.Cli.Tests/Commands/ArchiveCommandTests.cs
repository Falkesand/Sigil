using System.IO.Compression;
using Sigil.Signing;

namespace Sigil.Cli.Tests.Commands;

public class ArchiveCommandTests : IDisposable
{
    private readonly string _tempDir;

    public ArchiveCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-archcli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    // --- sign-archive tests ---

    [Fact]
    public async Task SignArchive_Zip_ProducesSignatureFile()
    {
        var archivePath = CreateZipArchive("test.zip",
            ("file1.txt", "hello"),
            ("file2.txt", "world"));

        var result = await CommandTestHelper.InvokeAsync("sign-archive", archivePath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Archive signed: 2 entries", result.StdOut);
        Assert.Contains("Output:", result.StdOut);

        var sigPath = archivePath + ".archive.sig.json";
        Assert.True(File.Exists(sigPath));

        var envelope = ArchiveSigner.Deserialize(File.ReadAllText(sigPath));
        Assert.Equal("archive", envelope.Kind);
        Assert.Equal(2, envelope.Subjects.Count);
        Assert.Single(envelope.Signatures);
    }

    [Fact]
    public async Task SignArchive_CustomOutput()
    {
        var archivePath = CreateZipArchive("custom.zip", ("data.txt", "data"));
        var outputPath = Path.Combine(_tempDir, "custom.sig.json");

        var result = await CommandTestHelper.InvokeAsync(
            "sign-archive", archivePath, "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(outputPath));
    }

    [Fact]
    public async Task SignArchive_WithLabel()
    {
        var archivePath = CreateZipArchive("labeled.zip", ("f.txt", "content"));
        var outputPath = Path.Combine(_tempDir, "labeled.sig.json");

        var result = await CommandTestHelper.InvokeAsync(
            "sign-archive", archivePath, "--label", "release-v1", "--output", outputPath);

        Assert.Equal(0, result.ExitCode);

        var envelope = ArchiveSigner.Deserialize(File.ReadAllText(outputPath));
        Assert.Equal("release-v1", envelope.Signatures[0].Label);
    }

    [Fact]
    public async Task SignArchive_WithPersistentKey()
    {
        var archivePath = CreateZipArchive("keyed.zip", ("k.txt", "keyed"));

        var keysDir = Path.Combine(_tempDir, "keys");
        Directory.CreateDirectory(keysDir);
        var keyPrefix = Path.Combine(keysDir, "archive-key");
        var genResult = await CommandTestHelper.InvokeAsync("generate", "-o", keyPrefix);
        Assert.Equal(0, genResult.ExitCode);

        var keyPath = keyPrefix + ".pem";
        var outputPath = Path.Combine(_tempDir, "keyed.sig.json");

        var result = await CommandTestHelper.InvokeAsync(
            "sign-archive", archivePath, "--key", keyPath, "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.DoesNotContain("ephemeral", result.StdOut, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(outputPath));
    }

    [Fact]
    public async Task SignArchive_NonExistentFile_ShowsError()
    {
        var fakePath = Path.Combine(_tempDir, "nonexistent.zip");

        var result = await CommandTestHelper.InvokeAsync("sign-archive", fakePath);

        Assert.NotEmpty(result.StdErr);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignArchive_UnrecognizedFormat_ShowsError()
    {
        var path = Path.Combine(_tempDir, "notarchive.txt");
        File.WriteAllText(path, "I am not an archive");

        var result = await CommandTestHelper.InvokeAsync("sign-archive", path);

        Assert.NotEmpty(result.StdErr);
        Assert.Contains("Unrecognized", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    // --- verify-archive tests ---

    [Fact]
    public async Task VerifyArchive_Valid_ShowsVerified()
    {
        var archivePath = CreateZipArchive("verify.zip",
            ("v1.txt", "verify1"),
            ("v2.txt", "verify2"));

        await CommandTestHelper.InvokeAsync("sign-archive", archivePath);

        var result = await CommandTestHelper.InvokeAsync("verify-archive", archivePath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[OK] v1.txt", result.StdOut);
        Assert.Contains("[OK] v2.txt", result.StdOut);
        Assert.Contains("[VERIFIED]", result.StdOut);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyArchive_TamperedContent_ShowsFailed()
    {
        var archivePath = CreateZipArchive("tamper.zip",
            ("data.txt", "original"));

        var sigPath = archivePath + ".archive.sig.json";
        await CommandTestHelper.InvokeAsync("sign-archive", archivePath);

        // Tamper: recreate the archive
        CreateZipArchive("tamper.zip", ("data.txt", "MODIFIED"));

        var result = await CommandTestHelper.InvokeAsync("verify-archive", archivePath);

        Assert.Contains("[FAIL] data.txt", result.StdOut);
    }

    [Fact]
    public async Task VerifyArchive_MissingSignature_ShowsError()
    {
        var archivePath = CreateZipArchive("nosig.zip", ("f.txt", "content"));

        var result = await CommandTestHelper.InvokeAsync("verify-archive", archivePath);

        Assert.NotEmpty(result.StdErr);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyArchive_CustomSignaturePath()
    {
        var archivePath = CreateZipArchive("custom-verify.zip", ("d.txt", "data"));
        var sigPath = Path.Combine(_tempDir, "custom.archive.sig.json");

        await CommandTestHelper.InvokeAsync(
            "sign-archive", archivePath, "--output", sigPath);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-archive", archivePath, "--signature", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[OK]", result.StdOut);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyArchive_WithTrustBundle_ShowsTrusted()
    {
        var archivePath = CreateZipArchive("trusted.zip", ("t.txt", "trusted content"));
        var sigPath = archivePath + ".archive.sig.json";

        await CommandTestHelper.InvokeAsync("sign-archive", archivePath);

        var envelope = ArchiveSigner.Deserialize(File.ReadAllText(sigPath));
        var fp = envelope.Signatures[0].KeyId;

        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", fp, "--name", "test-key");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-archive", archivePath, "--trust-bundle", bundlePath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[TRUSTED]", result.StdOut);
    }

    [Fact]
    public async Task VerifyArchive_WithPolicy_ShowsPolicyResult()
    {
        var archivePath = CreateZipArchive("policy.zip", ("p.txt", "policy test"));

        await CommandTestHelper.InvokeAsync("sign-archive", archivePath);

        var policyPath = Path.Combine(_tempDir, "policy.json");
        File.WriteAllText(policyPath, """
        {
            "version": "1.0",
            "rules": [
                { "require": "min-signatures", "count": 1 }
            ]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-archive", archivePath, "--policy", policyPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy Evaluation:", result.StdOut);
        Assert.Contains("[PASS]", result.StdOut);
        Assert.Contains("All policy rules PASSED", result.StdOut);
    }

    // --- Helpers ---

    private string CreateZipArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
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
}
