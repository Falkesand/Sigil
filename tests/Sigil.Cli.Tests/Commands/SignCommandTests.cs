namespace Sigil.Cli.Tests.Commands;

public class SignCommandTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public SignCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-cli-test-" + Guid.NewGuid().ToString("N")[..8]);
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
    public async Task Sign_produces_signature_file()
    {
        var result = await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
        Assert.True(File.Exists(_artifactPath + ".sig.json"), "Signature file should exist");
    }

    [Fact]
    public async Task Sign_ephemeral_shows_mode()
    {
        var result = await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        Assert.Contains("ephemeral", result.StdOut);
    }

    [Fact]
    public async Task Sign_with_persistent_key()
    {
        var prefix = Path.Combine(_tempDir, "key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix);

        var sigPath = Path.Combine(_tempDir, "test-artifact.txt.persistent.sig.json");
        var result = await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--key", prefix + ".pem", "--output", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(sigPath));
        Assert.DoesNotContain("ephemeral", result.StdOut);
    }

    [Fact]
    public async Task Sign_missing_artifact_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("sign", Path.Combine(_tempDir, "nonexistent.bin"));

        Assert.Contains("Artifact not found", result.StdErr);
    }

    [Fact]
    public async Task Sign_custom_output_path()
    {
        var customPath = Path.Combine(_tempDir, "custom.sig.json");
        var result = await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--output", customPath);

        Assert.True(File.Exists(customPath));
        Assert.Contains("Signature:", result.StdOut);
    }

    [Fact]
    public async Task Sign_EncryptedKey_WithAlgorithmHint_Succeeds()
    {
        var prefix = Path.Combine(_tempDir, "enc-key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "test-pass");

        var sigPath = Path.Combine(_tempDir, "hint.sig.json");
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--key", prefix + ".pem",
            "--passphrase", "test-pass",
            "--algorithm", "ecdsa-p256",
            "--output", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(sigPath));
        Assert.Contains("Signed:", result.StdOut);
    }

    [Fact]
    public async Task Sign_EncryptedKey_WrongPassphrase_ShowsPassphraseError()
    {
        var prefix = Path.Combine(_tempDir, "enc-key2");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "correct-pass");

        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--key", prefix + ".pem",
            "--passphrase", "wrong-pass");

        Assert.Contains("passphrase", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Sign_ExistingEnvelope_AppendsSignature()
    {
        var prefix1 = Path.Combine(_tempDir, "key1");
        var prefix2 = Path.Combine(_tempDir, "key2");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix1);
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix2, "--algorithm", "ecdsa-p384");

        var sigPath = Path.Combine(_tempDir, "multi.sig.json");

        // First signature
        await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--key", prefix1 + ".pem", "--output", sigPath);

        // Second signature — should append, not overwrite
        await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--key", prefix2 + ".pem", "--output", sigPath);

        var json = File.ReadAllText(sigPath);
        var envelope = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(json);
        var signatures = envelope.GetProperty("signatures");

        Assert.Equal(2, signatures.GetArrayLength());
    }

    [Fact]
    public async Task Sign_ExistingEnvelope_BothSignaturesVerify()
    {
        var prefix1 = Path.Combine(_tempDir, "key-a");
        var prefix2 = Path.Combine(_tempDir, "key-b");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix1);
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix2, "--algorithm", "ecdsa-p384");

        var sigPath = Path.Combine(_tempDir, "multi-verify.sig.json");

        await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--key", prefix1 + ".pem", "--output", sigPath);
        await CommandTestHelper.InvokeAsync("sign", _artifactPath, "--key", prefix2 + ".pem", "--output", sigPath);

        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath, "--signature", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("All signatures VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task Sign_PassphraseFile_ReadsFromFile()
    {
        var prefix = Path.Combine(_tempDir, "pf-key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "file-pass");

        var passFile = Path.Combine(_tempDir, "pass.txt");
        File.WriteAllText(passFile, "file-pass\n");

        var sigPath = Path.Combine(_tempDir, "pf.sig.json");
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--key", prefix + ".pem",
            "--passphrase-file", passFile,
            "--output", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
    }

    [Fact]
    public async Task Sign_EnvVar_ReadsPassphrase()
    {
        var prefix = Path.Combine(_tempDir, "env-key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "env-pass");

        var sigPath = Path.Combine(_tempDir, "env.sig.json");
        var result = await CommandTestHelper.InvokeWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = "env-pass" },
            "sign", _artifactPath,
            "--key", prefix + ".pem",
            "--output", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
    }

    [Fact]
    public async Task Sign_EnvVarFile_ReadsPassphrase()
    {
        var prefix = Path.Combine(_tempDir, "envf-key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "envf-pass");

        var passFile = Path.Combine(_tempDir, "envf-pass.txt");
        File.WriteAllText(passFile, "envf-pass\r\n");

        var sigPath = Path.Combine(_tempDir, "envf.sig.json");
        var result = await CommandTestHelper.InvokeWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE_FILE"] = passFile },
            "sign", _artifactPath,
            "--key", prefix + ".pem",
            "--output", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
    }

    [Fact]
    public async Task Sign_ExistingPassphrase_StillWorks()
    {
        var prefix = Path.Combine(_tempDir, "bp-key");
        await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "back-compat");

        var sigPath = Path.Combine(_tempDir, "bp.sig.json");
        var result = await CommandTestHelper.InvokeAsync(
            "sign", _artifactPath,
            "--key", prefix + ".pem",
            "--passphrase", "back-compat",
            "--output", sigPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Signed:", result.StdOut);
    }
}
