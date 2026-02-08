namespace Sigil.Cli.Tests.Commands;

public class VerifyCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public VerifyCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-cli-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "test artifact content for verification");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Verify_shows_VERIFIED_for_valid_signature()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("Digests: MATCH", result.StdOut);
    }

    [Fact]
    public async Task Verify_tampered_file_shows_FAILED()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Tamper with the artifact after signing
        File.WriteAllText(_artifactPath, "tampered content");

        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("FAILED", result.StdErr);
        Assert.Contains("digest mismatch", result.StdErr);
    }

    [Fact]
    public async Task Verify_missing_artifact_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("verify", Path.Combine(_tempDir, "nonexistent.bin"));

        Assert.Contains("Artifact not found", result.StdErr);
    }

    [Fact]
    public async Task Verify_missing_signature_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("Signature file not found", result.StdErr);
    }

    [Fact]
    public async Task Verify_trust_bundle_and_discover_mutually_exclusive()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--trust-bundle", "bundle.json",
            "--discover", "example.com");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Verify_trust_bundle_requires_authority()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var dummyBundle = Path.Combine(_tempDir, "bundle.json");
        File.WriteAllText(dummyBundle, """{"version":"1.0","kind":"trust-bundle","metadata":{"name":"test","created":"2024-01-01"}}""");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--trust-bundle", dummyBundle);

        Assert.Contains("--authority is required", result.StdErr);
    }
}
