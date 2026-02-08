namespace Sigil.Cli.Tests.Commands;

public class GenerateCommandTests : IDisposable
{
    private readonly string _tempDir;

    public GenerateCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-cli-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Generate_outputs_private_key_to_stdout()
    {
        var result = await CommandTestHelper.InvokeAsync("generate");

        Assert.Contains("BEGIN PRIVATE KEY", result.StdOut);
        Assert.Contains("Fingerprint:", result.StdErr);
    }

    [Fact]
    public async Task Generate_with_output_creates_files()
    {
        var prefix = Path.Combine(_tempDir, "testkey");
        var result = await CommandTestHelper.InvokeAsync("generate", "-o", prefix);

        Assert.True(File.Exists(prefix + ".pem"), "Private key file should exist");
        Assert.True(File.Exists(prefix + ".pub.pem"), "Public key file should exist");
        Assert.Contains("Private key:", result.StdOut);
        Assert.Contains("Public key:", result.StdOut);
    }

    [Fact]
    public async Task Generate_with_passphrase_encrypts_key()
    {
        var prefix = Path.Combine(_tempDir, "encrypted");
        var result = await CommandTestHelper.InvokeAsync("generate", "-o", prefix, "--passphrase", "test123");

        var pemContent = File.ReadAllText(prefix + ".pem");
        Assert.Contains("ENCRYPTED", pemContent);
        Assert.Contains("encrypted with passphrase", result.StdOut);
    }

    [Fact]
    public async Task Generate_with_algorithm_uses_specified()
    {
        var result = await CommandTestHelper.InvokeAsync("generate", "--algorithm", "ecdsa-p384");

        Assert.Contains("BEGIN PRIVATE KEY", result.StdOut);
    }

    [Fact]
    public async Task Generate_unknown_algorithm_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("generate", "--algorithm", "quantum-magic");

        Assert.Contains("Unknown algorithm", result.StdErr);
        Assert.Contains("Supported:", result.StdErr);
    }
}
