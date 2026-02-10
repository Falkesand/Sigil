namespace Sigil.Cli.Tests.Commands;

public class SignLogOptionTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public SignLogOptionTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "test artifact content");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Sign_with_invalid_log_url_shows_warning()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--log-url", "https://nonexistent.log.invalid");

        // Should succeed (best-effort) but show warning
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
        Assert.Contains("Warning:", result.StdErr);
    }

    [Fact]
    public async Task Sign_with_log_url_sigil_server_no_api_key_shows_warning()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--log-url", "https://log.example.com");

        // Should show warning about missing API key
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Warning:", result.StdErr);
        Assert.Contains("API key", result.StdErr);
    }

    [Fact]
    public async Task Sign_without_log_url_does_not_log()
    {
        var result = await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        Assert.Equal(0, result.ExitCode);
        Assert.DoesNotContain("Logged:", result.StdOut);
        Assert.DoesNotContain("log submission", result.StdErr.ToLowerInvariant());
    }

    [Fact]
    public async Task Sign_with_rekor_shorthand_shows_warning_on_failure()
    {
        // Rekor will fail (no network), should be best-effort
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--log-url", "rekor");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
        // Should either succeed or show warning
        var hasLog = result.StdOut.Contains("Logged:");
        var hasWarning = result.StdErr.Contains("Warning:");
        Assert.True(hasLog || hasWarning,
            "Should either log successfully or show a warning");
    }

    [Fact]
    public async Task SignManifest_accepts_log_url_option()
    {
        var file1 = Path.Combine(_tempDir, "file1.txt");
        File.WriteAllText(file1, "content1");

        var result = await CommandTestHelper.InvokeAsync(
            "sign-manifest", _tempDir,
            "--log-url", "https://nonexistent.log.invalid",
            "--log-api-key", "key123");

        // Should succeed with warning
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Warning:", result.StdErr);
    }
}
