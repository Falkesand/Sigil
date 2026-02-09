using Sigil.Cli.Commands;
using Sigil.Crypto;
using Sigil.Git;

namespace Sigil.Cli.Tests.Commands.Git;

public class GitSignProgramVerifyTests : IDisposable
{
    private readonly string _tempDir;

    public GitSignProgramVerifyTests()
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

    private static (string armored, string commitContent) SignCommit(string keyPath)
    {
        var commitContent = "tree abc123\nauthor Test <test@example.com>\n\nTest commit\n";
        var stdin = new StringReader(commitContent);
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        GitSignProgram.Run(
            ["git-sign", "--key", keyPath, "--status-fd=2"],
            stdin, stdout, stderr);

        return (stdout.ToString(), commitContent);
    }

    [Fact]
    public void Verify_valid_signature_emits_GOODSIG()
    {
        var keyPath = GenerateKeyFile();
        var (armored, commitContent) = SignCommit(keyPath);

        var sigFile = Path.Combine(_tempDir, "sig.tmp");
        File.WriteAllText(sigFile, armored);

        var stdin = new StringReader(commitContent);
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = GitSignProgram.Run(
            ["git-sign", "--key", keyPath, "--status-fd=1", "--verify", sigFile, "-"],
            stdin, stdout, stderr);

        Assert.Equal(0, exitCode);
        var output = stdout.ToString();
        Assert.Contains("[GNUPG:] GOODSIG", output);
        Assert.Contains("[GNUPG:] VALIDSIG", output);
        Assert.Contains("[GNUPG:] TRUST_UNDEFINED", output);
    }

    [Fact]
    public void Verify_tampered_content_emits_BADSIG()
    {
        var keyPath = GenerateKeyFile();
        var (armored, _) = SignCommit(keyPath);

        var sigFile = Path.Combine(_tempDir, "sig.tmp");
        File.WriteAllText(sigFile, armored);

        // Tampered content — different from what was signed
        var stdin = new StringReader("tampered content that was not signed");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = GitSignProgram.Run(
            ["git-sign", "--key", keyPath, "--status-fd=1", "--verify", sigFile, "-"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("[GNUPG:] BADSIG", stdout.ToString());
    }

    [Fact]
    public void Verify_invalid_armor_fails()
    {
        var keyPath = GenerateKeyFile();
        var sigFile = Path.Combine(_tempDir, "bad.sig");
        File.WriteAllText(sigFile, "not a valid signature");

        var stdin = new StringReader("content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = GitSignProgram.Run(
            ["git-sign", "--key", keyPath, "--verify", sigFile, "-"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("Error", stderr.ToString());
    }

    [Fact]
    public void Verify_missing_sigfile_fails()
    {
        var keyPath = GenerateKeyFile();
        var nonexistent = Path.Combine(_tempDir, "does-not-exist.sig");

        var stdin = new StringReader("content");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = GitSignProgram.Run(
            ["git-sign", "--key", keyPath, "--verify", nonexistent, "-"],
            stdin, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Contains("Error", stderr.ToString());
    }

    [Fact]
    public void Verify_status_fd_2_writes_to_stderr()
    {
        var keyPath = GenerateKeyFile();
        var (armored, commitContent) = SignCommit(keyPath);

        var sigFile = Path.Combine(_tempDir, "sig.tmp");
        File.WriteAllText(sigFile, armored);

        var stdin = new StringReader(commitContent);
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exitCode = GitSignProgram.Run(
            ["git-sign", "--key", keyPath, "--status-fd=2", "--verify", sigFile, "-"],
            stdin, stdout, stderr);

        Assert.Equal(0, exitCode);
        var errOutput = stderr.ToString();
        Assert.Contains("[GNUPG:] GOODSIG", errOutput);
        Assert.DoesNotContain("[GNUPG:]", stdout.ToString());
    }
}
