using System.Text.Json;

namespace Sigil.Cli.Tests.Commands;

public class AttestCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;
    private readonly string _predicatePath;

    public AttestCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-att-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "attestation test content");

        _predicatePath = Path.Combine(_tempDir, "predicate.json");
        var predicate = new { builder = new { id = "github-actions" }, buildType = "https://slsa.dev/build/v1" };
        File.WriteAllText(_predicatePath, JsonSerializer.Serialize(predicate));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Attest_produces_att_json_file()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Attested:", result.StdOut);
        Assert.True(File.Exists(_artifactPath + ".att.json"), "Attestation file should exist");
    }

    [Fact]
    public async Task Attest_ephemeral_mode_default()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1");

        Assert.Contains("ephemeral", result.StdOut);
    }

    [Fact]
    public async Task Attest_with_persistent_key()
    {
        var prefix = Path.Combine(_tempDir, "key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix);

        var attPath = Path.Combine(_tempDir, "signed.att.json");
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1",
            "--key", prefix + ".pem",
            "--output", attPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(attPath));
        Assert.DoesNotContain("ephemeral", result.StdOut);
    }

    [Fact]
    public async Task Attest_custom_output_path()
    {
        var customPath = Path.Combine(_tempDir, "custom.att.json");
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1",
            "--output", customPath);

        Assert.True(File.Exists(customPath));
        Assert.Contains("Attestation:", result.StdOut);
    }

    [Fact]
    public async Task Attest_missing_artifact_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", Path.Combine(_tempDir, "nonexistent.bin"),
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1");

        Assert.Contains("Artifact not found", result.StdErr);
    }

    [Fact]
    public async Task Attest_missing_predicate_file_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", Path.Combine(_tempDir, "missing-predicate.json"),
            "--type", "slsa-provenance-v1");

        Assert.Contains("Predicate file not found", result.StdErr);
    }

    [Fact]
    public async Task Attest_invalid_predicate_type_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "not-a-real-type");

        Assert.Contains("Unknown predicate type", result.StdErr);
    }

    [Fact]
    public async Task Attest_custom_uri_predicate_type()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "https://example.com/custom-predicate/v1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Attested:", result.StdOut);
    }

    [Fact]
    public async Task Attest_existing_envelope_appends_signature()
    {
        var prefix1 = Path.Combine(_tempDir, "key1");
        var prefix2 = Path.Combine(_tempDir, "key2");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix1);
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix2, "--algorithm", "ecdsa-p384");

        var attPath = Path.Combine(_tempDir, "multi.att.json");

        // First attestation
        await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1",
            "--key", prefix1 + ".pem",
            "--output", attPath);

        // Second attestation — should append
        await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1",
            "--key", prefix2 + ".pem",
            "--output", attPath);

        var json = File.ReadAllText(attPath);
        var envelope = JsonSerializer.Deserialize<JsonElement>(json);
        var signatures = envelope.GetProperty("signatures");

        Assert.Equal(2, signatures.GetArrayLength());
    }

    [Fact]
    public async Task Attest_with_invalid_predicate_json_shows_error()
    {
        var badPredicatePath = Path.Combine(_tempDir, "bad-predicate.json");
        File.WriteAllText(badPredicatePath, "not json {{{");

        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", badPredicatePath,
            "--type", "slsa-provenance-v1");

        Assert.Contains("Invalid predicate JSON", result.StdErr);
    }

    [Fact]
    public async Task Attest_output_contains_dsse_structure()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1");

        var attPath = _artifactPath + ".att.json";
        var json = File.ReadAllText(attPath);
        var doc = JsonSerializer.Deserialize<JsonElement>(json);

        Assert.Equal("application/vnd.in-toto+json", doc.GetProperty("payloadType").GetString());
        Assert.True(doc.TryGetProperty("payload", out _));
        Assert.True(doc.TryGetProperty("signatures", out _));
    }

    [Fact]
    public async Task Attest_with_different_algorithm()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "attest", _artifactPath,
            "--predicate", _predicatePath,
            "--type", "slsa-provenance-v1",
            "--algorithm", "ecdsa-p384");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("ecdsa-p384", result.StdOut);
    }
}
