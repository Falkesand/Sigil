namespace Sigil.Cli.Tests.Commands;

public class LogShowCommandTests
{
    [Fact]
    public async Task Show_displays_entries()
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

            var result = await CommandTestHelper.InvokeAsync("log", "show", "--log", logPath);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Showing 1 entries", result.StdOut);
            Assert.Contains("test.dll", result.StdOut);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Show_nonexistent_log_fails()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        var logPath = Path.Combine(tempDir, "nonexistent.jsonl");

        var result = await CommandTestHelper.InvokeAsync("log", "show", "--log", logPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }
}
