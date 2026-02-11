using System.Text;
using Sigil.Cli.Commands;
using Sigil.Crypto;
using Sigil.Git;

namespace Sigil.Cli.Tests.Commands.Git;

public class GitSignProgramSignTests : IDisposable
{
    private readonly string _tempDir;

    public GitSignProgramSignTests()
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
    public async Task Sign_produces_armored_output()
    {
        var keyPath = GenerateKeyFile();
        var commitContent = "tree abc123\nauthor Test <test@example.com>\n\nInitial commit\n";
        var stdin = new StringReader(commitContent);
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--key", keyPath, "--status-fd=2", "-bsau", "test@example.com"],
            stdin, stdout, stderr);

        Assert.Equal(0, exitCode);
        var output = stdout.ToString();
        Assert.Contains("-----BEGIN SIGNED MESSAGE-----", output);
        Assert.Contains("-----END SIGNED MESSAGE-----", output);
    }

    [Fact]
    public async Task Sign_emits_SIG_CREATED_status()
    {
        var keyPath = GenerateKeyFile();
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--key", keyPath, "--status-fd=2", "-bsau", "test@example.com"],
            stdin, stdout, stderr);

        Assert.Equal(0, exitCode);
        Assert.Contains("[GNUPG:] SIG_CREATED", stderr.ToString());
    }

    [Fact]
    public async Task Sign_roundtrip_produces_valid_envelope()
    {
        var keyPath = GenerateKeyFile();
        var commitContent = "tree abc123\nauthor Test <test@example.com>\n\nTest commit\n";
        var stdin = new StringReader(commitContent);
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        await GitSignProgram.RunAsync(
            ["git-sign", "--key", keyPath],
            stdin, stdout, stderr);

        var armored = stdout.ToString();
        var unwrapResult = GitSignatureArmor.Unwrap(armored);
        Assert.True(unwrapResult.IsSuccess);

        var envelope = Sigil.Signing.ArtifactSigner.Deserialize(unwrapResult.Value);
        Assert.Equal("git-object", envelope.Subject.Name);
        Assert.Single(envelope.Signatures);
        Assert.Equal("ecdsa-p256", envelope.Signatures[0].Algorithm);
    }

    [Fact]
    public async Task Sign_fails_without_key()
    {
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--status-fd=2", "-bsau", "test@example.com"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("--key, --vault/--vault-key, or --cert-store required", stderr.ToString());
    }

    [Fact]
    public async Task Sign_fails_on_empty_stdin()
    {
        var keyPath = GenerateKeyFile();
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--key", keyPath],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("No data", stderr.ToString());
    }

    [Fact]
    public async Task Sign_with_key_equals_syntax()
    {
        var keyPath = GenerateKeyFile();
        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", $"--key={keyPath}", "--status-fd=2", "-bsau", "test@example.com"],
            stdin, stdout, stderr);

        Assert.Equal(0, exitCode);
        Assert.Contains("-----BEGIN SIGNED MESSAGE-----", stdout.ToString());
    }

    [Fact]
    public async Task Sign_PassphraseFile_Works()
    {
        var keyPath = GenerateEncryptedKeyFile("pf-pass");
        var passFile = Path.Combine(_tempDir, "pass.txt");
        File.WriteAllText(passFile, "pf-pass\n");

        var stdin = new StringReader("commit content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = await GitSignProgram.RunAsync(
            ["git-sign", "--key", keyPath, "--passphrase-file", passFile],
            stdin, stdout, stderr);

        Assert.Equal(0, exitCode);
        Assert.Contains("-----BEGIN SIGNED MESSAGE-----", stdout.ToString());
    }

    [Fact]
    public async Task Sign_EnvVarFile_Works()
    {
        var keyPath = GenerateEncryptedKeyFile("evf-pass");
        var passFile = Path.Combine(_tempDir, "envf-pass.txt");
        File.WriteAllText(passFile, "evf-pass");

        var exitCode = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE_FILE"] = passFile },
            async () =>
            {
                var stdin = new StringReader("commit content");
                var stdout = new StringWriter();
                var stderr = new StringWriter();

                var code = await GitSignProgram.RunAsync(
                    ["git-sign", "--key", keyPath],
                    stdin, stdout, stderr);

                Assert.Contains("-----BEGIN SIGNED MESSAGE-----", stdout.ToString());
                return code;
            });

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task Sign_SigilPassphraseEnvVar_StillWorks()
    {
        var keyPath = GenerateEncryptedKeyFile("env-pass");

        var exitCode = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = "env-pass" },
            async () =>
            {
                var stdin = new StringReader("commit content");
                var stdout = new StringWriter();
                var stderr = new StringWriter();

                var code = await GitSignProgram.RunAsync(
                    ["git-sign", "--key", keyPath],
                    stdin, stdout, stderr);

                Assert.Contains("-----BEGIN SIGNED MESSAGE-----", stdout.ToString());
                return code;
            });

        Assert.Equal(0, exitCode);
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
