namespace Sigil.Cli.Tests.Commands;

public class VaultSignCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public VaultSignCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-cli-vault-test-" + Guid.NewGuid().ToString("N")[..8]);
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
    public async Task Sign_vault_and_key_mutually_exclusive()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--key", "some.pem", "--vault", "hashicorp", "--vault-key", "transit/mykey");

        Assert.Contains("Cannot use both --key and --vault", result.StdErr);
    }

    [Fact]
    public async Task Sign_vault_requires_vault_key()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--vault", "hashicorp");

        Assert.Contains("--vault-key is required when using --vault", result.StdErr);
    }

    [Fact]
    public async Task Sign_vault_key_requires_vault()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--vault-key", "transit/mykey");

        Assert.Contains("--vault is required when using --vault-key", result.StdErr);
    }

    [Fact]
    public async Task Sign_unknown_vault_provider_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath, "--vault", "unknown", "--vault-key", "mykey");

        Assert.Contains("Unknown vault provider: unknown", result.StdErr);
    }

    [Fact]
    public async Task TrustSign_vault_and_key_mutually_exclusive()
    {
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        // Create a minimal trust bundle
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", bundlePath);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "sign", bundlePath, "--key", "some.pem", "--vault", "hashicorp", "--vault-key", "transit/mykey");

        Assert.Contains("Cannot use both --key and --vault", result.StdErr);
    }

    [Fact]
    public async Task TrustSign_requires_key_or_vault()
    {
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", bundlePath);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "sign", bundlePath);

        Assert.Contains("Either --key, --vault, or --cert-store is required", result.StdErr);
    }

    [Fact]
    public async Task TrustSign_vault_requires_vault_key()
    {
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", bundlePath);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "sign", bundlePath, "--vault", "aws");

        Assert.Contains("--vault-key is required when using --vault", result.StdErr);
    }

    [Fact]
    public async Task TrustSign_unknown_vault_provider_shows_error()
    {
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test-bundle", "-o", bundlePath);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "sign", bundlePath, "--vault", "unknown", "--vault-key", "mykey");

        Assert.Contains("Unknown vault provider: unknown", result.StdErr);
    }
}
