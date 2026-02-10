using Sigil.Crypto;

namespace Sigil.Cli.Tests.Commands.Git;

public class GitConfigCommandTests : IDisposable
{
    private readonly string _tempDir;

    public GitConfigCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sigil-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private string GenerateKeyFile()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var pemPath = Path.Combine(_tempDir, "test.private.pem");
        var pemBytes = signer.ExportPrivateKeyPemBytes();
        File.WriteAllBytes(pemPath, pemBytes);
        return pemPath;
    }

    [Fact]
    public async Task Config_with_valid_key_succeeds()
    {
        var keyPath = GenerateKeyFile();

        var result = await CommandTestHelper.InvokeAsync("git", "config", "--key", keyPath);

        Assert.Contains("Git signing configured", result.StdOut);
        Assert.Contains("Wrapper:", result.StdOut);
    }

    [Fact]
    public async Task Config_shows_fingerprint()
    {
        var keyPath = GenerateKeyFile();

        var result = await CommandTestHelper.InvokeAsync("git", "config", "--key", keyPath);

        Assert.Contains("Key: sha256:", result.StdOut);
    }

    [Fact]
    public async Task Config_with_nonexistent_key_fails()
    {
        var fakePath = Path.Combine(_tempDir, "nonexistent.pem");

        var result = await CommandTestHelper.InvokeAsync("git", "config", "--key", fakePath);

        Assert.Contains("not found", result.StdErr);
    }

    [Fact]
    public async Task Config_global_flag_outputs_global_scope()
    {
        var keyPath = GenerateKeyFile();

        var result = await CommandTestHelper.InvokeAsync("git", "config", "--key", keyPath, "--global");

        Assert.Contains("Scope: global", result.StdOut);
    }

    [Fact]
    public async Task Config_local_flag_shows_tip()
    {
        var keyPath = GenerateKeyFile();

        var result = await CommandTestHelper.InvokeAsync("git", "config", "--key", keyPath);

        Assert.Contains("Scope: local", result.StdOut);
        Assert.Contains("Tip:", result.StdOut);
    }

    [Fact]
    public async Task Config_vault_and_key_mutually_exclusive()
    {
        var keyPath = GenerateKeyFile();

        var result = await CommandTestHelper.InvokeAsync(
            "git", "config", "--key", keyPath, "--vault", "hashicorp", "--vault-key", "transit/key");

        Assert.Contains("Cannot use both --key and --vault", result.StdErr);
    }

    [Fact]
    public async Task Config_vault_requires_vault_key()
    {
        var result = await CommandTestHelper.InvokeAsync("git", "config", "--vault", "hashicorp");

        Assert.Contains("--vault-key is required", result.StdErr);
    }

    [Fact]
    public async Task Config_requires_key_or_vault()
    {
        var result = await CommandTestHelper.InvokeAsync("git", "config");

        Assert.Contains("--key, --vault/--vault-key, or --cert-store is required", result.StdErr);
    }

    [Fact]
    public async Task Config_wrapper_does_not_contain_passphrase()
    {
        var keyPath = GenerateEncryptedKeyFile("secret-pass");

        var result = await CommandTestHelper.InvokeAsync(
            "git", "config", "--key", keyPath, "--passphrase", "secret-pass");

        Assert.Contains("Git signing configured", result.StdOut);
        Assert.Contains("Note: Key requires a passphrase", result.StdErr);
        Assert.DoesNotContain("Warning: Passphrase is stored", result.StdErr);

        // Read the wrapper script and verify no passphrase embedded
        var wrapperLine = result.StdOut.Split('\n')
            .FirstOrDefault(l => l.Contains("Wrapper:"));
        Assert.NotNull(wrapperLine);
        var wrapperPath = wrapperLine!.Split("Wrapper:")[1].Trim();
        var wrapperContent = File.ReadAllText(wrapperPath);
        Assert.DoesNotContain("secret-pass", wrapperContent);
        Assert.DoesNotContain("--passphrase", wrapperContent);
    }

    [Fact]
    public async Task Config_passphrase_file_works()
    {
        var keyPath = GenerateEncryptedKeyFile("file-pass");
        var passFile = Path.Combine(_tempDir, "pass.txt");
        File.WriteAllText(passFile, "file-pass\n");

        var result = await CommandTestHelper.InvokeAsync(
            "git", "config", "--key", keyPath, "--passphrase-file", passFile);

        Assert.Contains("Git signing configured", result.StdOut);
    }

    [Fact]
    public async Task Config_existing_paths_still_work()
    {
        var keyPath = GenerateKeyFile();

        var result = await CommandTestHelper.InvokeAsync("git", "config", "--key", keyPath);

        Assert.Contains("Git signing configured", result.StdOut);
        Assert.DoesNotContain("Note: Key requires a passphrase", result.StdErr);
    }

    private string GenerateEncryptedKeyFile(string passphrase)
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var pemPath = Path.Combine(_tempDir, $"enc-{Guid.NewGuid():N}.pem");
        var pemBytes = signer.ExportEncryptedPrivateKeyPemBytes(passphrase.ToCharArray());
        File.WriteAllBytes(pemPath, pemBytes);
        return pemPath;
    }
}
