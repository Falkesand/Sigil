using System.Text.Json;

namespace Sigil.Cli.Tests.Commands;

public class VerifyAttestationCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;
    private readonly string _predicatePath;

    public VerifyAttestationCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-vatt-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "verify attestation test content");

        _predicatePath = Path.Combine(_tempDir, "predicate.json");
        var predicate = new { builder = new { id = "github-actions" } };
        File.WriteAllText(_predicatePath, JsonSerializer.Serialize(predicate));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private async Task CreateAttestation(string? outputPath = null, string? keyPrefix = null)
    {
        var args = new List<string>
        {
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1"
        };

        if (outputPath is not null)
        {
            args.Add("--output");
            args.Add(outputPath);
        }

        if (keyPrefix is not null)
        {
            args.Add("--key");
            args.Add(keyPrefix + ".pem");
        }

        await CommandTestHelper.InvokeAsync(args.ToArray());
    }

    [Fact]
    public async Task VerifyAttestation_valid_succeeds()
    {
        await CreateAttestation();

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Digests: MATCH", result.StdOut);
        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyAttestation_custom_attestation_path()
    {
        var attPath = Path.Combine(_tempDir, "custom.att.json");
        await CreateAttestation(attPath);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--attestation", attPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyAttestation_missing_artifact_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", Path.Combine(_tempDir, "nonexistent.bin"));

        Assert.Contains("Artifact not found", result.StdErr);
    }

    [Fact]
    public async Task VerifyAttestation_missing_attestation_file_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath);

        Assert.Contains("Attestation file not found", result.StdErr);
    }

    [Fact]
    public async Task VerifyAttestation_tampered_artifact_fails()
    {
        await CreateAttestation();

        // Tamper with the artifact
        File.WriteAllText(_artifactPath, "tampered content");

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath);

        Assert.Contains("FAILED", result.StdErr);
        Assert.Contains("digest mismatch", result.StdErr);
    }

    [Fact]
    public async Task VerifyAttestation_shows_predicate_type()
    {
        await CreateAttestation();

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath);

        Assert.Contains("Predicate Type: https://slsa.dev/provenance/v1", result.StdOut);
    }

    [Fact]
    public async Task VerifyAttestation_type_filter_matching()
    {
        await CreateAttestation();

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--type", "slsa-provenance-v1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyAttestation_type_filter_mismatch()
    {
        await CreateAttestation();

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--type", "cyclonedx");

        Assert.Contains("Predicate type mismatch", result.StdErr);
    }

    [Fact]
    public async Task VerifyAttestation_with_persistent_key_verifies()
    {
        var prefix = Path.Combine(_tempDir, "key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix);

        var attPath = Path.Combine(_tempDir, "persistent.att.json");
        await CreateAttestation(attPath, prefix);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--attestation", attPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyAttestation_multiple_signatures_both_verified()
    {
        var prefix1 = Path.Combine(_tempDir, "key-a");
        var prefix2 = Path.Combine(_tempDir, "key-b");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix1);
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix2, "--algorithm", "ecdsa-p384");

        var attPath = Path.Combine(_tempDir, "multi.att.json");
        await CreateAttestation(attPath, prefix1);

        // Append second signature
        await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1",
            "--key", prefix2 + ".pem",
            "--output", attPath);

        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath,
            "--attestation", attPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }
}
