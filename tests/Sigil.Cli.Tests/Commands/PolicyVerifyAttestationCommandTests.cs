using System.Text.Json;

namespace Sigil.Cli.Tests.Commands;

public class PolicyVerifyAttestationCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;
    private readonly string _predicatePath;

    public PolicyVerifyAttestationCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-patt-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "attestation policy test content");

        _predicatePath = Path.Combine(_tempDir, "predicate.json");
        var predicate = new { builder = new { id = "github-actions" } };
        File.WriteAllText(_predicatePath, JsonSerializer.Serialize(predicate));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private async Task CreateAttestation()
    {
        await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1");
    }

    [Fact]
    public async Task Policy_mutually_exclusive_with_trust_bundle()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("""{ "version": "1.0", "rules": [{ "require": "timestamp" }] }""");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath,
            "--trust-bundle", "bundle.json");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Policy_mutually_exclusive_with_discover()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("""{ "version": "1.0", "rules": [{ "require": "timestamp" }] }""");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath,
            "--discover", "example.com");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Policy_missing_file_shows_error()
    {
        await CreateAttestation();

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", Path.Combine(_tempDir, "nonexistent.json"));

        Assert.Contains("Policy file not found", result.StdErr);
    }

    [Fact]
    public async Task Policy_invalid_json_shows_error()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("not json");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("Invalid policy", result.StdErr);
    }

    [Fact]
    public async Task Policy_min_signatures_passes()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "min-signatures", "count": 1 }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] min-signatures", result.StdOut);
        Assert.Contains("All policy rules PASSED", result.StdOut);
    }

    [Fact]
    public async Task Policy_algorithm_passes()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "algorithm", "allowed": ["ecdsa-p256"] }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] algorithm", result.StdOut);
    }

    [Fact]
    public async Task Policy_sbom_metadata_not_applicable()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "sbom-metadata" }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[FAIL] sbom-metadata", result.StdOut);
        Assert.Contains("not applicable", result.StdOut);
    }

    [Fact]
    public async Task Policy_multiple_rules_evaluated()
    {
        await CreateAttestation();
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [
            { "require": "min-signatures", "count": 1 },
            { "require": "algorithm", "allowed": ["ecdsa-p256"] },
            { "require": "timestamp" }
          ]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] min-signatures", result.StdOut);
        Assert.Contains("[PASS] algorithm", result.StdOut);
        Assert.Contains("[FAIL] timestamp", result.StdOut);
        Assert.Contains("Policy evaluation FAILED", result.StdOut);
    }

    private string WritePolicyFile(string content)
    {
        var path = Path.Combine(_tempDir, "policy.json");
        File.WriteAllText(path, content);
        return path;
    }
}
