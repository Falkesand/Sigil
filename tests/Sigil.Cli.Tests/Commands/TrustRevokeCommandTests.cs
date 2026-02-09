namespace Sigil.Cli.Tests.Commands;

public class TrustRevokeCommandTests : IDisposable
{
    private readonly string _tempDir;

    public TrustRevokeCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-revoke-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Revoke_adds_entry_to_bundle()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", "sha256:abc123");

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123", "--reason", "Key compromised");

        Assert.Contains("Revoked key sha256:abc123", result.StdOut);

        var json = File.ReadAllText(bundlePath);
        Assert.Contains("sha256:abc123", json);
        Assert.Contains("Key compromised", json);
        Assert.Contains("revokedAt", json);
    }

    [Fact]
    public async Task Revoke_without_reason_succeeds()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", "sha256:abc123");

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123");

        Assert.Contains("Revoked key sha256:abc123", result.StdOut);
    }

    [Fact]
    public async Task Revoke_fails_on_signed_bundle()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);

        // Generate a key and sign the bundle
        await CommandTestHelper.InvokeAsync("generate", "-o", Path.Combine(_tempDir, "authority"));
        var keyPath = Path.Combine(_tempDir, "authority.pem");
        await CommandTestHelper.InvokeAsync("trust", "sign", bundlePath, "--key", keyPath);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123", "--reason", "test");

        Assert.Contains("Cannot modify a signed bundle", result.StdErr);
    }

    [Fact]
    public async Task Revoke_fails_on_missing_bundle()
    {
        var bundlePath = Path.Combine(_tempDir, "nonexistent.json");

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123", "--reason", "test");

        Assert.Contains("Bundle not found", result.StdErr);
    }

    [Fact]
    public async Task Revoke_duplicate_fingerprint_adds_second_entry()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);

        await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123", "--reason", "First");
        await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123", "--reason", "Second");

        var json = File.ReadAllText(bundlePath);
        var bundle = System.Text.Json.JsonSerializer.Deserialize<Sigil.Trust.TrustBundle>(json);

        Assert.Equal(2, bundle!.Revocations.Count);
    }

    [Fact]
    public async Task Show_displays_revocations()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "sha256:abc123", "--reason", "Compromised");

        var result = await CommandTestHelper.InvokeAsync("trust", "show", bundlePath);

        Assert.Contains("Revocations (1):", result.StdOut);
        Assert.Contains("sha256:abc123", result.StdOut);
        Assert.Contains("Compromised", result.StdOut);
    }
}
