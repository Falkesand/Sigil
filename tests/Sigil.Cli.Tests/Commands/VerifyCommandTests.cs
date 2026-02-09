namespace Sigil.Cli.Tests.Commands;

public class VerifyCommandTests : IDisposable
{
    private static readonly System.Text.Json.JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _tempDir;
    private readonly string _artifactPath;

    public VerifyCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-cli-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "test artifact content for verification");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Verify_shows_VERIFIED_for_valid_signature()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("Digests: MATCH", result.StdOut);
    }

    [Fact]
    public async Task Verify_tampered_file_shows_FAILED()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Tamper with the artifact after signing
        File.WriteAllText(_artifactPath, "tampered content");

        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("FAILED", result.StdErr);
        Assert.Contains("digest mismatch", result.StdErr);
    }

    [Fact]
    public async Task Verify_missing_artifact_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("verify", Path.Combine(_tempDir, "nonexistent.bin"));

        Assert.Contains("Artifact not found", result.StdErr);
    }

    [Fact]
    public async Task Verify_missing_signature_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("Signature file not found", result.StdErr);
    }

    [Fact]
    public async Task Verify_trust_bundle_and_discover_mutually_exclusive()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--trust-bundle", "bundle.json",
            "--discover", "example.com");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Verify_trust_bundle_requires_authority_for_signed_bundle()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var dummyBundle = Path.Combine(_tempDir, "bundle.json");
        // Bundle with a signature field present — authority is required
        File.WriteAllText(dummyBundle, """{"version":"1.0","kind":"trust-bundle","metadata":{"name":"test","created":"2024-01-01"},"signature":{"keyId":"abc","algorithm":"ecdsa-p256","publicKey":"AAAA","value":"BBBB","timestamp":"2024-01-01T00:00:00Z"}}""");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--trust-bundle", dummyBundle);

        Assert.Contains("--authority is required", result.StdErr);
    }

    [Fact]
    public async Task Verify_with_trust_bundle_shows_REVOKED_for_revoked_key()
    {
        // Sign the artifact
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Read the signature to get the key fingerprint
        var sigPath = _artifactPath + ".sig.json";
        var sigJson = File.ReadAllText(sigPath);
        var envelope = System.Text.Json.JsonSerializer.Deserialize<Sigil.Signing.SignatureEnvelope>(sigJson);
        var fingerprint = envelope!.Signatures[0].KeyId;

        // Create a trust bundle with the key AND a revocation for it
        var bundlePath = Path.Combine(_tempDir, "trust.json");
        await CommandTestHelper.InvokeAsync("trust", "create", "--name", "test", "-o", bundlePath);
        await CommandTestHelper.InvokeAsync("trust", "add", bundlePath, "--fingerprint", fingerprint);

        // Add a revocation manually (bundle is unsigned, so we can modify it)
        var bundleJson = File.ReadAllText(bundlePath);
        var bundle = System.Text.Json.JsonSerializer.Deserialize<Sigil.Trust.TrustBundle>(bundleJson);
        bundle!.Revocations.Add(new Sigil.Trust.RevocationEntry
        {
            Fingerprint = fingerprint,
            RevokedAt = "2026-02-09T10:00:00Z",
            Reason = "Testing revocation"
        });
        File.WriteAllText(bundlePath, System.Text.Json.JsonSerializer.Serialize(bundle, s_jsonOptions));

        // Verify without --authority (unsigned bundle, no signature check needed)
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath,
            "--trust-bundle", bundlePath);

        Assert.Contains("REVOKED", result.StdOut);
    }
}
