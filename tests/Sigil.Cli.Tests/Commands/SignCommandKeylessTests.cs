namespace Sigil.Cli.Tests.Commands;

public class SignCommandKeylessTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public SignCommandKeylessTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-keyless-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test.txt");
        File.WriteAllText(_artifactPath, "test content");
    }

    [Fact]
    public async Task Keyless_WithoutTimestamp_Error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--keyless");

        Assert.Contains("--timestamp is required", result.StdErr);
    }

    [Fact]
    public async Task Keyless_WithKey_MutualExclusivity()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--keyless", "--key", "key.pem",
            "--timestamp", "http://tsa.example.com");

        Assert.Contains("Cannot use both --keyless and --key", result.StdErr);
    }

    [Fact]
    public async Task Keyless_WithVault_MutualExclusivity()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--keyless", "--vault", "azure",
            "--vault-key", "key1", "--timestamp", "http://tsa.example.com");

        Assert.Contains("Cannot use both --keyless and --vault", result.StdErr);
    }

    [Fact]
    public async Task OidcToken_WithoutKeyless_Error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--oidc-token", "some-token");

        Assert.Contains("--oidc-token requires --keyless", result.StdErr);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { /* cleanup */ }
    }
}
