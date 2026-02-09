namespace Sigil.Cli.Tests.Commands;

public class LogSearchCommandTests
{
    [Fact]
    public async Task Search_by_key_finds_entry()
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

            // Read the log to get the key id
            var logLines = File.ReadAllLines(logPath);
            var entry = System.Text.Json.JsonSerializer.Deserialize<Sigil.Transparency.LogEntry>(logLines[0])!;

            var result = await CommandTestHelper.InvokeAsync(
                "log", "search", "--log", logPath, "--key", entry.KeyId);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Found 1 entries", result.StdOut);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Search_no_results()
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

            var result = await CommandTestHelper.InvokeAsync(
                "log", "search", "--log", logPath, "--key", "sha256:nonexistent");

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Found 0 entries", result.StdOut);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Search_no_filter_shows_error()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

        var result = await CommandTestHelper.InvokeAsync(
            "log", "search", "--log", logPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("filter", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }
}
