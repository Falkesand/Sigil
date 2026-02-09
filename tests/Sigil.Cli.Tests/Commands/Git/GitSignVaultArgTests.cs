using System.Security.Cryptography;
using System.Text;
using Sigil.Cli.Commands;
using Sigil.Crypto;

namespace Sigil.Cli.Tests.Commands.Git;

public class GitSignVaultArgTests : IDisposable
{
    private readonly string _tempDir;

    public GitSignVaultArgTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sigil-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Sign_vault_and_key_mutually_exclusive()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--key", "k.pem", "--vault", "hashicorp", "--vault-key", "transit/my-key"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("Cannot use both --key and --vault", stderr.ToString());
    }

    [Fact]
    public async Task Sign_vault_requires_vault_key()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--vault", "hashicorp"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("--vault-key is required", stderr.ToString());
    }

    [Fact]
    public async Task Sign_vault_key_requires_vault()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--vault-key", "transit/my-key"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("--vault is required", stderr.ToString());
    }

    [Fact]
    public async Task Sign_vault_unknown_provider()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--vault", "unknown", "--vault-key", "some-key"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("Unknown vault provider", stderr.ToString());
    }

    [Fact]
    public async Task Sign_requires_key_or_vault()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--status-fd=2", "-bsau", "test@example.com"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("--key or --vault/--vault-key required", stderr.ToString());
    }

    [Fact]
    public async Task Sign_sigil_passphrase_env_var()
    {
        const string passphrase = "test-env-passphrase";

        // Generate encrypted PEM key
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var pemPath = Path.Combine(_tempDir, "encrypted.pem");
        var encryptedPem = signer.ExportEncryptedPrivateKeyPemBytes(passphrase);
        File.WriteAllBytes(pemPath, encryptedPem);

        var originalEnv = Environment.GetEnvironmentVariable("SIGIL_PASSPHRASE");
        try
        {
            Environment.SetEnvironmentVariable("SIGIL_PASSPHRASE", passphrase);

            var stdin = new StringReader("commit content for env var test");
            var stdout = new StringWriter();
            var stderr = new StringWriter();

            // No --passphrase arg — should pick up SIGIL_PASSPHRASE env var
            var exitCode = await GitSignProgram.RunAsync(
                ["git-sign", "--key", pemPath],
                stdin, stdout, stderr);

            Assert.Equal(0, exitCode);
            Assert.Contains("-----BEGIN SIGNED MESSAGE-----", stdout.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGIL_PASSPHRASE", originalEnv);
        }
    }

    [Fact]
    public async Task Sign_passphrase_arg_overrides_env()
    {
        const string correctPassphrase = "correct-passphrase";
        const string wrongPassphrase = "wrong-env-passphrase";

        // Generate encrypted PEM key with correct passphrase
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var pemPath = Path.Combine(_tempDir, "encrypted.pem");
        var encryptedPem = signer.ExportEncryptedPrivateKeyPemBytes(correctPassphrase);
        File.WriteAllBytes(pemPath, encryptedPem);

        var originalEnv = Environment.GetEnvironmentVariable("SIGIL_PASSPHRASE");
        try
        {
            // Set wrong passphrase in env, correct one as arg
            Environment.SetEnvironmentVariable("SIGIL_PASSPHRASE", wrongPassphrase);

            var stdin = new StringReader("commit content for override test");
            var stdout = new StringWriter();
            var stderr = new StringWriter();

            var exitCode = await GitSignProgram.RunAsync(
                ["git-sign", "--key", pemPath, "--passphrase", correctPassphrase],
                stdin, stdout, stderr);

            Assert.Equal(0, exitCode);
            Assert.Contains("-----BEGIN SIGNED MESSAGE-----", stdout.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGIL_PASSPHRASE", originalEnv);
        }
    }

    [Fact]
    public async Task Sign_vault_equals_syntax()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--vault=unknown", "--vault-key=some-key"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("Unknown vault provider", stderr.ToString());
    }
}
