namespace Sigil.Cli.Tests.Commands;

public class TrustRevokeCommandTests : IDisposable
{
    private const string ValidFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", ValidFingerprint);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", "Key compromised");

        Assert.Contains($"Revoked key {ValidFingerprint}", result.StdOut);

        var json = File.ReadAllText(bundlePath);
        Assert.Contains(ValidFingerprint, json);
        Assert.Contains("Key compromised", json);
        Assert.Contains("revokedAt", json);
    }

    [Fact]
    public async Task Revoke_without_reason_succeeds()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", ValidFingerprint);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint);

        Assert.Contains($"Revoked key {ValidFingerprint}", result.StdOut);
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
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", "test");

        Assert.Contains("Cannot modify a signed bundle", result.StdErr);
    }

    [Fact]
    public async Task Revoke_fails_on_missing_bundle()
    {
        var bundlePath = Path.Combine(_tempDir, "nonexistent.json");

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", "test");

        Assert.Contains("Bundle not found", result.StdErr);
    }

    [Fact]
    public async Task Revoke_rejects_invalid_fingerprint_format()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);

        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", "not-a-valid-fingerprint", "--reason", "test");

        Assert.Contains("Invalid fingerprint format", result.StdErr);
    }

    [Fact]
    public async Task Revoke_rejects_reason_exceeding_max_length()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);

        var longReason = new string('x', 1025);
        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", longReason);

        Assert.Contains("Reason must not exceed 1024 characters", result.StdErr);
    }

    [Fact]
    public async Task Revoke_warns_on_duplicate_fingerprint()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);

        await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", "First");
        var result = await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", "Second");

        Assert.Contains("already revoked", result.StdErr);

        var json = File.ReadAllText(bundlePath);
        var bundle = System.Text.Json.JsonSerializer.Deserialize<Sigil.Trust.TrustBundle>(json);

        // Should NOT add a second entry
        Assert.Single(bundle!.Revocations);
    }

    [Fact]
    public async Task Show_displays_revocations()
    {
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync(
            "trust", "revoke", bundlePath, "--fingerprint", ValidFingerprint, "--reason", "Compromised");

        var result = await CommandTestHelper.InvokeAsync("trust", "show", bundlePath);

        Assert.Contains("Revocations (1):", result.StdOut);
        Assert.Contains(ValidFingerprint, result.StdOut);
        Assert.Contains("Compromised", result.StdOut);
    }
}
