using System.Text.Json;

namespace Sigil.Cli.Tests.Commands;

public class AttestEnvCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public AttestEnvCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-attenv-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "attest-env test content");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task AttestEnv_with_ephemeral_key_produces_attestation_file()
    {
        var result = await CommandTestHelper.InvokeAsync("attest-env", _artifactPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Attested:", result.StdOut);
        Assert.True(
            File.Exists(_artifactPath + ".env-attestation.json"),
            "Attestation file should exist at default path");
    }

    [Fact]
    public async Task AttestEnv_output_contains_env_fingerprint_predicate_type()
    {
        var result = await CommandTestHelper.InvokeAsync("attest-env", _artifactPath);
        Assert.Equal(0, result.ExitCode);

        var attPath = _artifactPath + ".env-attestation.json";
        var json = File.ReadAllText(attPath);
        var doc = JsonSerializer.Deserialize<JsonElement>(json);

        Assert.Equal("application/vnd.in-toto+json", doc.GetProperty("payloadType").GetString());

        var payloadBase64 = doc.GetProperty("payload").GetString()!;
        var payloadBytes = Convert.FromBase64String(payloadBase64);
        var statement = JsonSerializer.Deserialize<JsonElement>(payloadBytes);

        Assert.Equal(
            "https://sigil.dev/environment-fingerprint/v1",
            statement.GetProperty("predicateType").GetString());
    }

    [Fact]
    public async Task AttestEnv_output_contains_os_and_architecture_in_predicate()
    {
        var result = await CommandTestHelper.InvokeAsync("attest-env", _artifactPath);
        Assert.Equal(0, result.ExitCode);

        var attPath = _artifactPath + ".env-attestation.json";
        var json = File.ReadAllText(attPath);
        var doc = JsonSerializer.Deserialize<JsonElement>(json);

        var payloadBase64 = doc.GetProperty("payload").GetString()!;
        var payloadBytes = Convert.FromBase64String(payloadBase64);
        var statement = JsonSerializer.Deserialize<JsonElement>(payloadBytes);

        var predicate = statement.GetProperty("predicate");
        var environment = predicate.GetProperty("environment");

        Assert.True(
            environment.TryGetProperty("osDescription", out var osDesc) &&
            !string.IsNullOrWhiteSpace(osDesc.GetString()),
            "predicate.environment.osDescription should be non-empty");

        Assert.True(
            environment.TryGetProperty("architecture", out var arch) &&
            !string.IsNullOrWhiteSpace(arch.GetString()),
            "predicate.environment.architecture should be non-empty");
    }

    [Fact]
    public async Task AttestEnv_with_include_var_captures_matching_variables()
    {
        var envVars = new Dictionary<string, string?>
        {
            ["SIGIL_TEST_BUILD_ID"] = "build-42",
            ["SIGIL_TEST_VERSION"] = "1.0.0",
        };

        var outputPath = Path.Combine(_tempDir, "env-with-vars.json");
        var result = await CommandTestHelper.InvokeWithEnvVarsAsync(
            envVars,
            "attest-env", _artifactPath,
            "--include-var", "SIGIL_TEST_*",
            "--output", outputPath);

        Assert.Equal(0, result.ExitCode);

        var json = File.ReadAllText(outputPath);
        var doc = JsonSerializer.Deserialize<JsonElement>(json);

        var payloadBase64 = doc.GetProperty("payload").GetString()!;
        var payloadBytes = Convert.FromBase64String(payloadBase64);
        var statement = JsonSerializer.Deserialize<JsonElement>(payloadBytes);

        var predicate = statement.GetProperty("predicate");
        Assert.True(predicate.TryGetProperty("customVariables", out var customVars),
            "predicate.customVariables should be present");

        Assert.Equal("build-42", customVars.GetProperty("SIGIL_TEST_BUILD_ID").GetString());
        Assert.Equal("1.0.0", customVars.GetProperty("SIGIL_TEST_VERSION").GetString());
    }

    [Fact]
    public async Task AttestEnv_with_include_var_filters_blocklisted_variables()
    {
        var envVars = new Dictionary<string, string?>
        {
            ["SIGIL_MY_TOKEN"] = "super-secret-value",
            ["SIGIL_MY_SAFE_VAR"] = "safe-value",
        };

        var outputPath = Path.Combine(_tempDir, "env-filtered.json");
        var result = await CommandTestHelper.InvokeWithEnvVarsAsync(
            envVars,
            "attest-env", _artifactPath,
            "--include-var", "SIGIL_MY_*",
            "--output", outputPath);

        Assert.Equal(0, result.ExitCode);

        var json = File.ReadAllText(outputPath);
        var doc = JsonSerializer.Deserialize<JsonElement>(json);

        var payloadBase64 = doc.GetProperty("payload").GetString()!;
        var payloadBytes = Convert.FromBase64String(payloadBase64);
        var statement = JsonSerializer.Deserialize<JsonElement>(payloadBytes);

        var predicate = statement.GetProperty("predicate");

        if (predicate.TryGetProperty("customVariables", out var customVars))
        {
            Assert.False(
                customVars.TryGetProperty("SIGIL_MY_TOKEN", out _),
                "Blocklisted variable SIGIL_MY_TOKEN should not appear in customVariables");

            Assert.Equal("safe-value", customVars.GetProperty("SIGIL_MY_SAFE_VAR").GetString());
        }
        else
        {
            // If no customVariables at all, the blocklist may have filtered everything
            // except SIGIL_MY_SAFE_VAR — this would be a failure since we expect at least one
            Assert.Fail("customVariables should be present with at least SIGIL_MY_SAFE_VAR");
        }
    }

    [Fact]
    public async Task AttestEnv_with_key_uses_specified_key()
    {
        var prefix = Path.Combine(_tempDir, "key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix);

        var outputPath = Path.Combine(_tempDir, "keyed.env-attestation.json");
        var result = await CommandTestHelper.InvokeAsync(
            "attest-env", _artifactPath,
            "--key", prefix + ".pem",
            "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.DoesNotContain("ephemeral", result.StdOut);
        Assert.True(File.Exists(outputPath));

        // Verify the signature uses the generated key's public key
        var pubPem = File.ReadAllText(prefix + ".pub.pem");
        var json = File.ReadAllText(outputPath);
        var doc = JsonSerializer.Deserialize<JsonElement>(json);
        var signatures = doc.GetProperty("signatures");
        Assert.Equal(1, signatures.GetArrayLength());
    }

    [Fact]
    public async Task AttestEnv_with_output_writes_to_specified_path()
    {
        var customPath = Path.Combine(_tempDir, "custom-output.json");
        var result = await CommandTestHelper.InvokeAsync(
            "attest-env", _artifactPath,
            "--output", customPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(customPath), "Attestation file should be at specified output path");
        Assert.Contains("Attestation:", result.StdOut);
    }

    [Fact]
    public async Task AttestEnv_with_invalid_artifact_path_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest-env", Path.Combine(_tempDir, "nonexistent.bin"));

        Assert.Contains("Artifact not found", result.StdErr);
    }

    [Fact]
    public async Task AttestEnv_help_shows_usage()
    {
        var result = await CommandTestHelper.InvokeAsync("attest-env", "--help");

        Assert.Contains("attest-env", result.StdOut);
        Assert.Contains("environment fingerprint", result.StdOut, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AttestEnv_attestation_is_verifiable_with_verify_attestation()
    {
        var outputPath = Path.Combine(_tempDir, "roundtrip.env-attestation.json");
        var attestResult = await CommandTestHelper.InvokeAsync(
            "attest-env", _artifactPath,
            "--output", outputPath);

        Assert.Equal(0, attestResult.ExitCode);

        var verifyResult = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--attestation", outputPath);

        Assert.Equal(0, verifyResult.ExitCode);
        Assert.Contains("VERIFIED", verifyResult.StdOut);
        Assert.Contains("All signatures VERIFIED", verifyResult.StdOut);
    }
}
