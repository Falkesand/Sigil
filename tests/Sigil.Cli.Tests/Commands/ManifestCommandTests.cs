using Sigil.Signing;

namespace Sigil.Cli.Tests.Commands;

public class ManifestCommandTests : IDisposable
{
    private readonly string _tempDir;

    public ManifestCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-manifest-cli-" + Guid.NewGuid().ToString("N")[..8]);
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

    // --- sign-manifest tests ---

    [Fact]
    public async Task SignManifest_Directory_ProducesManifestFile()
    {
        CreateFile("file1.txt", "hello");
        CreateFile("file2.txt", "world");
        CreateFile("sub/file3.txt", "nested");

        var result = await CommandTestHelper.InvokeAsync("sign-manifest", _tempDir);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Manifest signed: 3 files", result.StdOut);
        Assert.Contains("Output:", result.StdOut);

        var outputPath = Path.Combine(_tempDir, "manifest.sig.json");
        Assert.True(File.Exists(outputPath));

        var envelope = ManifestSigner.Deserialize(File.ReadAllText(outputPath));
        Assert.Equal(3, envelope.Subjects.Count);
        Assert.Single(envelope.Signatures);
    }

    [Fact]
    public async Task SignManifest_WithIncludeFilter()
    {
        CreateFile("app.dll", "binary");
        CreateFile("app.pdb", "debug");
        CreateFile("lib.dll", "library");

        var outputPath = Path.Combine(_tempDir, "filtered.sig.json");
        var result = await CommandTestHelper.InvokeAsync(
            "sign-manifest", _tempDir, "--include", "*.dll", "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Manifest signed: 2 files", result.StdOut);

        var envelope = ManifestSigner.Deserialize(File.ReadAllText(outputPath));
        Assert.Equal(2, envelope.Subjects.Count);
        Assert.All(envelope.Subjects, s => Assert.EndsWith(".dll", s.Name));
    }

    [Fact]
    public async Task SignManifest_CustomOutput()
    {
        CreateFile("data.txt", "data");

        var customPath = Path.Combine(_tempDir, "custom", "my-manifest.json");
        Directory.CreateDirectory(Path.GetDirectoryName(customPath)!);

        var result = await CommandTestHelper.InvokeAsync(
            "sign-manifest", _tempDir, "--output", customPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(customPath));
    }

    [Fact]
    public async Task SignManifest_WithPersistentKey()
    {
        // Use a separate directory for signing content vs keys
        var dataDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(dataDir);
        File.WriteAllText(Path.Combine(dataDir, "code.cs"), "class C {}");

        // Generate a key in a separate keys directory
        var keysDir = Path.Combine(_tempDir, "keys");
        Directory.CreateDirectory(keysDir);
        var keyPrefix = Path.Combine(keysDir, "test-key");
        var genResult = await CommandTestHelper.InvokeAsync("generate", "-o", keyPrefix);
        Assert.Equal(0, genResult.ExitCode);

        var keyPath = keyPrefix + ".pem";
        var outputPath = Path.Combine(_tempDir, "signed.manifest.sig.json");
        var result = await CommandTestHelper.InvokeAsync(
            "sign-manifest", dataDir,
            "--key", keyPath,
            "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.DoesNotContain("ephemeral", result.StdOut, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(outputPath));
    }

    [Fact]
    public async Task SignManifest_EmptyDirectory_ShowsError()
    {
        var emptyDir = Path.Combine(_tempDir, "empty");
        Directory.CreateDirectory(emptyDir);

        var result = await CommandTestHelper.InvokeAsync("sign-manifest", emptyDir);

        Assert.NotEmpty(result.StdErr);
        Assert.Contains("No files found", result.StdErr);
    }

    [Fact]
    public async Task SignManifest_NonExistentPath_ShowsError()
    {
        var fakePath = Path.Combine(_tempDir, "nonexistent");

        var result = await CommandTestHelper.InvokeAsync("sign-manifest", fakePath);

        Assert.NotEmpty(result.StdErr);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignManifest_WithLabel()
    {
        CreateFile("labeled.txt", "labeled content");

        var outputPath = Path.Combine(_tempDir, "labeled.sig.json");
        var result = await CommandTestHelper.InvokeAsync(
            "sign-manifest", _tempDir, "--label", "ci-build", "--output", outputPath);

        Assert.Equal(0, result.ExitCode);

        var envelope = ManifestSigner.Deserialize(File.ReadAllText(outputPath));
        Assert.Equal("ci-build", envelope.Signatures[0].Label);
    }

    // --- verify-manifest tests ---

    [Fact]
    public async Task VerifyManifest_ValidManifest_ShowsVerified()
    {
        var dataDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(dataDir);
        File.WriteAllText(Path.Combine(dataDir, "v1.txt"), "verify1");
        File.WriteAllText(Path.Combine(dataDir, "v2.txt"), "verify2");

        var outputPath = Path.Combine(_tempDir, "manifest.sig.json");
        await CommandTestHelper.InvokeAsync("sign-manifest", dataDir, "--output", outputPath);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-manifest", outputPath, "--base-path", dataDir);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[OK] v1.txt", result.StdOut);
        Assert.Contains("[OK] v2.txt", result.StdOut);
        Assert.Contains("[VERIFIED]", result.StdOut);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyManifest_TamperedFile_ShowsFailed()
    {
        var dataDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(dataDir);
        var file = Path.Combine(dataDir, "tamper.txt");
        File.WriteAllText(file, "original");

        var outputPath = Path.Combine(_tempDir, "manifest.sig.json");
        await CommandTestHelper.InvokeAsync("sign-manifest", dataDir, "--output", outputPath);

        // Tamper with file
        File.WriteAllText(file, "MODIFIED");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-manifest", outputPath, "--base-path", dataDir);

        Assert.Contains("[FAIL] tamper.txt", result.StdOut);
    }

    [Fact]
    public async Task VerifyManifest_MissingFile_ShowsError()
    {
        var dataDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(dataDir);
        var file = Path.Combine(dataDir, "disappear.txt");
        File.WriteAllText(file, "soon gone");

        var outputPath = Path.Combine(_tempDir, "manifest.sig.json");
        await CommandTestHelper.InvokeAsync("sign-manifest", dataDir, "--output", outputPath);

        File.Delete(file);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-manifest", outputPath, "--base-path", dataDir);

        Assert.Contains("[FAIL] disappear.txt", result.StdOut);
    }

    [Fact]
    public async Task VerifyManifest_MissingManifest_ShowsError()
    {
        var fakePath = Path.Combine(_tempDir, "nonexistent.sig.json");

        var result = await CommandTestHelper.InvokeAsync("verify-manifest", fakePath);

        Assert.NotEmpty(result.StdErr);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyManifest_CustomBasePath()
    {
        var subDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(subDir);
        CreateFile("data/item.txt", "item content");

        var outputPath = Path.Combine(_tempDir, "remote.sig.json");
        await CommandTestHelper.InvokeAsync("sign-manifest", subDir, "--output", outputPath);

        // Verify from different location using --base-path
        var result = await CommandTestHelper.InvokeAsync(
            "verify-manifest", outputPath, "--base-path", subDir);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[OK] item.txt", result.StdOut);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyManifest_WithTrustBundle_ShowsTrusted()
    {
        var dataDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(dataDir);
        File.WriteAllText(Path.Combine(dataDir, "trusted.txt"), "trusted content");

        var outputPath = Path.Combine(_tempDir, "manifest.sig.json");
        await CommandTestHelper.InvokeAsync("sign-manifest", dataDir, "--output", outputPath);

        // Read the manifest to get the fingerprint
        var envelope = ManifestSigner.Deserialize(File.ReadAllText(outputPath));
        var fp = envelope.Signatures[0].KeyId;

        // Create unsigned trust bundle
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", fp, "--name", "test-key");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-manifest", outputPath, "--trust-bundle", bundlePath, "--base-path", dataDir);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[TRUSTED]", result.StdOut);
    }

    [Fact]
    public async Task VerifyManifest_WithPolicy_ShowsPolicyResult()
    {
        var dataDir = Path.Combine(_tempDir, "data");
        Directory.CreateDirectory(dataDir);
        File.WriteAllText(Path.Combine(dataDir, "policy-test.txt"), "policy test content");

        var outputPath = Path.Combine(_tempDir, "manifest.sig.json");
        await CommandTestHelper.InvokeAsync("sign-manifest", dataDir, "--output", outputPath);

        // Create a simple policy
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
            "verify-manifest", outputPath, "--policy", policyPath, "--base-path", dataDir);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Policy Evaluation:", result.StdOut);
        Assert.Contains("[PASS]", result.StdOut);
        Assert.Contains("All policy rules PASSED", result.StdOut);
    }
}
