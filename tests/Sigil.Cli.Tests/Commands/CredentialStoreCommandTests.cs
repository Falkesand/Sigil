using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests.Commands;

public class CredentialStoreCommandTests : IDisposable
{
    private readonly string _tempDir;

    public CredentialStoreCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-cred-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task CredentialStore_NonexistentKey_ReportsError()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "credential", "store", "--key", Path.Combine(_tempDir, "nonexistent.pem"));

        // On non-Windows, will fail with platform error; on Windows, with file not found
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(
            result.StdErr.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            result.StdErr.Contains("only supported on Windows", StringComparison.OrdinalIgnoreCase),
            $"Unexpected stderr: {result.StdErr}");
    }

    [Fact]
    public async Task CredentialRemove_NonexistentKey_ReportsNotFound()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "credential", "remove", "--key", Path.Combine(_tempDir, "nonexistent.pem"));

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(
            result.StdErr.Contains("No stored passphrase", StringComparison.OrdinalIgnoreCase) ||
            result.StdErr.Contains("only supported on Windows", StringComparison.OrdinalIgnoreCase) ||
            result.StdErr.Contains("not available", StringComparison.OrdinalIgnoreCase),
            $"Unexpected stderr: {result.StdErr}");
    }

    [Fact]
    public async Task CredentialList_RunsWithoutError()
    {
        var result = await CommandTestHelper.InvokeAsync("credential", "list");

        if (OperatingSystem.IsWindows())
        {
            // Should succeed even if empty
            Assert.Equal(0, result.ExitCode);
        }
        else
        {
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("only supported on Windows", result.StdErr, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void CredentialListCommand_TargetPrefix_IsCorrect()
    {
        Assert.Equal("sigil:passphrase:", CredentialListCommand.TargetPrefix);
    }
}
