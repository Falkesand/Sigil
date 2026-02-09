namespace Sigil.Cli.Tests.Commands;

public class LogVerifyCommandTests
{
    [Fact]
    public async Task Verify_valid_log_passes()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var artifactPath = Path.Combine(tempDir, "test.dll");
            File.WriteAllText(artifactPath, "test content");

            await CommandTestHelper.InvokeAsync("sign", artifactPath);

            var envelopePath = artifactPath + ".sig.json";
            var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

            await CommandTestHelper.InvokeAsync("log", "append", envelopePath, "--log", logPath);

            var result = await CommandTestHelper.InvokeAsync("log", "verify", "--log", logPath);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("integrity verified", result.StdOut, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Verify_tampered_log_fails()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var artifactPath = Path.Combine(tempDir, "test.dll");
            File.WriteAllText(artifactPath, "test content");

            await CommandTestHelper.InvokeAsync("sign", artifactPath);

            var envelopePath = artifactPath + ".sig.json";
            var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

            await CommandTestHelper.InvokeAsync("log", "append", envelopePath, "--log", logPath);

            // Tamper with the log
            var content = File.ReadAllText(logPath);
            content = content.Replace("test.dll", "tampered.dll");
            File.WriteAllText(logPath, content);

            var result = await CommandTestHelper.InvokeAsync("log", "verify", "--log", logPath);

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("INTEGRITY VIOLATION", result.StdErr);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Verify_nonexistent_log_fails()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        var logPath = Path.Combine(tempDir, "nonexistent.jsonl");

        var result = await CommandTestHelper.InvokeAsync("log", "verify", "--log", logPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }
}
