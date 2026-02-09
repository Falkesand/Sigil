namespace Sigil.Cli.Tests.Commands;

public class LogProofCommandTests
{
    private static async Task<string> SetupLogWithEntries(string tempDir, int count)
    {
        var logPath = Path.Combine(tempDir, ".sigil.log.jsonl");

        for (int i = 0; i < count; i++)
        {
            var artifactPath = Path.Combine(tempDir, $"file{i}.dll");
            File.WriteAllText(artifactPath, $"content {i}");

            await CommandTestHelper.InvokeAsync("sign", artifactPath);

            var envelopePath = artifactPath + ".sig.json";
            await CommandTestHelper.InvokeAsync("log", "append", envelopePath, "--log", logPath);
        }

        return logPath;
    }

    [Fact]
    public async Task Inclusion_proof_verifies()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var logPath = await SetupLogWithEntries(tempDir, 4);

            var result = await CommandTestHelper.InvokeAsync(
                "log", "proof", "--log", logPath, "--index", "1");

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Inclusion proof", result.StdOut);
            Assert.Contains("VERIFIED", result.StdOut);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Consistency_proof_verifies()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var logPath = await SetupLogWithEntries(tempDir, 4);

            var result = await CommandTestHelper.InvokeAsync(
                "log", "proof", "--log", logPath, "--old-size", "2");

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("Consistency proof", result.StdOut);
            Assert.Contains("VERIFIED", result.StdOut);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Proof_out_of_range_fails()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var logPath = await SetupLogWithEntries(tempDir, 2);

            var result = await CommandTestHelper.InvokeAsync(
                "log", "proof", "--log", logPath, "--index", "99");

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("out of range", result.StdErr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Proof_no_index_or_old_size_fails()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-log-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var logPath = await SetupLogWithEntries(tempDir, 2);

            var result = await CommandTestHelper.InvokeAsync(
                "log", "proof", "--log", logPath);

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("--index", result.StdErr);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
