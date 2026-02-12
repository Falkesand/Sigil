namespace Sigil.Cli.Tests.Commands;

public class BaselineLearnCommandTests : IDisposable
{
    private readonly string _tempDir;

    public BaselineLearnCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-baseline-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private static string CreateMinimalSigJson()
    {
        return """
        {"version":"1.0","subject":{"name":"test.txt","digests":{"sha256":"abc"}},"signatures":[{"keyId":"sha256:test123","algorithm":"ecdsa-p256","publicKey":"dGVzdA==","value":"c2ln","timestamp":"2026-02-10T14:30:00Z"}]}
        """;
    }

    [Fact]
    public async Task Learn_with_signatures_creates_baseline_file()
    {
        var scanDir = Path.Combine(_tempDir, "sigs");
        Directory.CreateDirectory(scanDir);
        File.WriteAllText(Path.Combine(scanDir, "test.sig.json"), CreateMinimalSigJson());

        var result = await CommandTestHelper.InvokeAsync(
            "baseline", "learn", "--scan", scanDir);

        Assert.Equal(0, result.ExitCode);

        var baselinePath = Path.Combine(scanDir, ".sigil.baseline.json");
        Assert.True(File.Exists(baselinePath));
        var content = File.ReadAllText(baselinePath);
        Assert.Contains("anomaly-baseline", content);
        Assert.Contains("Baseline learned from 1 signature file(s)", result.StdOut);
    }

    [Fact]
    public async Task Learn_with_no_signatures_creates_empty_baseline()
    {
        var scanDir = Path.Combine(_tempDir, "empty");
        Directory.CreateDirectory(scanDir);

        var result = await CommandTestHelper.InvokeAsync(
            "baseline", "learn", "--scan", scanDir);

        Assert.Equal(0, result.ExitCode);

        var baselinePath = Path.Combine(scanDir, ".sigil.baseline.json");
        Assert.True(File.Exists(baselinePath));
        var content = File.ReadAllText(baselinePath);
        Assert.Contains("\"sampleCount\": 0", content);
        Assert.Contains("Baseline learned from 0 signature file(s)", result.StdOut);
    }

    [Fact]
    public async Task Learn_with_custom_output_writes_to_specified_path()
    {
        var scanDir = Path.Combine(_tempDir, "sigs2");
        Directory.CreateDirectory(scanDir);
        File.WriteAllText(Path.Combine(scanDir, "test.sig.json"), CreateMinimalSigJson());

        var customOutput = Path.Combine(_tempDir, "custom.json");

        var result = await CommandTestHelper.InvokeAsync(
            "baseline", "learn", "--scan", scanDir, "--output", customOutput);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(customOutput));
        var content = File.ReadAllText(customOutput);
        Assert.Contains("anomaly-baseline", content);
        Assert.Contains($"Baseline written to: {customOutput}", result.StdOut);
    }

    [Fact]
    public async Task Learn_help_shows_usage()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "baseline", "learn", "--help");

        var combined = result.StdOut + result.StdErr;
        Assert.Contains("learn", combined);
        Assert.Contains("--scan", combined);
    }

    [Fact]
    public async Task Learn_with_nonexistent_dir_shows_error()
    {
        var nonExistent = Path.Combine(_tempDir, "does-not-exist");

        var result = await CommandTestHelper.InvokeAsync(
            "baseline", "learn", "--scan", nonExistent);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }
}
