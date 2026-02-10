namespace Sigil.Cli.Tests.Commands;

public class TrustIdentityCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _bundlePath;

    public TrustIdentityCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-identity-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _bundlePath = Path.Combine(_tempDir, "trust.json");
    }

    [Fact]
    public async Task IdentityAdd_CreatesEntry()
    {
        // Create bundle first
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", _bundlePath);

        var result = await CommandTestHelper.InvokeAsync("trust", "identity-add", _bundlePath,
            "--issuer", "https://token.actions.githubusercontent.com",
            "--subject", "repo:myorg/*",
            "--name", "GitHub CI");

        Assert.Contains("Added identity", result.StdOut);

        // Verify it shows up
        var showResult = await CommandTestHelper.InvokeAsync("trust", "show", _bundlePath);
        Assert.Contains("Identities (1)", showResult.StdOut);
        Assert.Contains("token.actions.githubusercontent.com", showResult.StdOut);
        Assert.Contains("repo:myorg/*", showResult.StdOut);
        Assert.Contains("GitHub CI", showResult.StdOut);
    }

    [Fact]
    public async Task IdentityAdd_ToSignedBundle_Rejected()
    {
        // Create and sign bundle
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", _bundlePath);
        await CommandTestHelper.InvokeAsync("generate", "-o", Path.Combine(_tempDir, "authority"));

        var keyPath = Path.Combine(_tempDir, "authority.pem");
        await CommandTestHelper.InvokeAsync("trust", "sign", _bundlePath, "--key", keyPath);

        var result = await CommandTestHelper.InvokeAsync("trust", "identity-add", _bundlePath,
            "--issuer", "https://issuer.example.com",
            "--subject", "*");

        Assert.Contains("Cannot modify a signed bundle", result.StdErr);
    }

    [Fact]
    public async Task IdentityRemove_Works()
    {
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", _bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "identity-add", _bundlePath,
            "--issuer", "https://issuer.example.com",
            "--subject", "repo:org/*");

        var result = await CommandTestHelper.InvokeAsync("trust", "identity-remove", _bundlePath,
            "--issuer", "https://issuer.example.com",
            "--subject", "repo:org/*");

        Assert.Contains("Removed identity", result.StdOut);

        // Verify it's gone
        var showResult = await CommandTestHelper.InvokeAsync("trust", "show", _bundlePath);
        Assert.DoesNotContain("Identities", showResult.StdOut);
    }

    [Fact]
    public async Task IdentityRemove_NotFound_ShowsError()
    {
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", _bundlePath);

        var result = await CommandTestHelper.InvokeAsync("trust", "identity-remove", _bundlePath,
            "--issuer", "https://issuer.example.com",
            "--subject", "nonexistent");

        Assert.Contains("Identity not found", result.StdErr);
    }

    [Fact]
    public async Task IdentityAdd_RequiredOptions()
    {
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", _bundlePath);

        // Missing --subject
        var result = await CommandTestHelper.InvokeAsync("trust", "identity-add", _bundlePath,
            "--issuer", "https://issuer.example.com");

        // System.CommandLine should report the missing required option
        Assert.True(result.StdErr.Length > 0 || result.ExitCode != 0);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { /* cleanup */ }
    }
}
