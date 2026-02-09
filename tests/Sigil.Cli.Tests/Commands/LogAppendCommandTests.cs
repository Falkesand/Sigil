namespace Sigil.Cli.Tests.Commands;

public class LogAppendCommandTests
{
    [Fact]
    public async Task Append_creates_log_entry()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var artifactPath = Path.Combine(tempDir, "test.dll");
            File.WriteAllText(artifactPath, "test content");

            var signResult = await CommandTestHelper.InvokeAsync("sign", artifactPath);
            Assert.Equal(0, signResult.ExitCode);

            var envelopePath = artifactPath + ".sig.json";
            var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

            var result = await CommandTestHelper.InvokeAsync(
                "log", "append", envelopePath, "--log", logPath);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Appended entry #0", result.StdOut);
            Assert.True(File.Exists(logPath));
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Append_duplicate_shows_error()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var artifactPath = Path.Combine(tempDir, "test.dll");
            File.WriteAllText(artifactPath, "test content");

            var signResult = await CommandTestHelper.InvokeAsync("sign", artifactPath);
            Assert.Equal(0, signResult.ExitCode);

            var envelopePath = artifactPath + ".sig.json";
            var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

            await CommandTestHelper.InvokeAsync("log", "append", envelopePath, "--log", logPath);
            var result = await CommandTestHelper.InvokeAsync("log", "append", envelopePath, "--log", logPath);

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("already logged", result.StdErr);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Append_missing_envelope_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "log", "append", "nonexistent.sig.json");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Append_invalid_signature_index_shows_error()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var artifactPath = Path.Combine(tempDir, "test.dll");
            File.WriteAllText(artifactPath, "test content");

            var signResult = await CommandTestHelper.InvokeAsync("sign", artifactPath);
            Assert.Equal(0, signResult.ExitCode);

            var envelopePath = artifactPath + ".sig.json";
            var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

            var result = await CommandTestHelper.InvokeAsync(
                "log", "append", envelopePath, "--log", logPath, "--signature-index", "99");

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("out of range", result.StdErr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
