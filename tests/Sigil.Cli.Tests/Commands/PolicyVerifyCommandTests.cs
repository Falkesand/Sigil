namespace Sigil.Cli.Tests.Commands;

public class PolicyVerifyCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public PolicyVerifyCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-policy-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "test artifact content for policy verification");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Policy_mutually_exclusive_with_trust_bundle()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("""{ "version": "1.0", "rules": [{ "require": "timestamp" }] }""");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath,
            "--trust-bundle", "bundle.json");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Policy_mutually_exclusive_with_discover()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("""{ "version": "1.0", "rules": [{ "require": "timestamp" }] }""");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath,
            "--discover", "example.com");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Policy_missing_file_shows_error()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", Path.Combine(_tempDir, "nonexistent.json"));

        Assert.Contains("Policy file not found", result.StdErr);
    }

    [Fact]
    public async Task Policy_invalid_json_shows_error()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("not json at all");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("Invalid policy", result.StdErr);
    }

    [Fact]
    public async Task Policy_min_signatures_passes()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "min-signatures", "count": 1 }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] min-signatures", result.StdOut);
        Assert.Contains("All policy rules PASSED", result.StdOut);
    }

    [Fact]
    public async Task Policy_min_signatures_fails_when_not_enough()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "min-signatures", "count": 5 }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[FAIL] min-signatures", result.StdOut);
        Assert.Contains("Policy evaluation FAILED", result.StdOut);
    }

    [Fact]
    public async Task Policy_algorithm_passes()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "algorithm", "allowed": ["ecdsa-p256"] }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] algorithm", result.StdOut);
    }

    [Fact]
    public async Task Policy_algorithm_fails_for_wrong_algorithm()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "algorithm", "allowed": ["rsa-pss-sha256"] }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[FAIL] algorithm", result.StdOut);
    }

    [Fact]
    public async Task Policy_multiple_rules_evaluated()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);
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
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] min-signatures", result.StdOut);
        Assert.Contains("[PASS] algorithm", result.StdOut);
        Assert.Contains("[FAIL] timestamp", result.StdOut);
        Assert.Contains("Policy evaluation FAILED", result.StdOut);
    }

    [Fact]
    public async Task Policy_label_with_matching_signature()
    {
        await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--label", "ci-build");
        var policyPath = WritePolicyFile("""
        {
          "version": "1.0",
          "rules": [{ "require": "label", "match": "ci-*" }]
        }
        """);

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath,
            "--policy", policyPath);

        Assert.Contains("[PASS] label", result.StdOut);
    }

    private string WritePolicyFile(string content)
    {
        var path = Path.Combine(_tempDir, "policy.json");
        File.WriteAllText(path, content);
        return path;
    }
}
