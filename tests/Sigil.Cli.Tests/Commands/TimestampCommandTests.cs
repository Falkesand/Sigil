namespace Sigil.Cli.Tests.Commands;

public class TimestampCommandTests
{
    [Fact]
    public async Task MissingEnvelope_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "timestamp", "nonexistent.sig.json", "--tsa", "http://localhost/tsa");

        Assert.Contains("not found", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InvalidIndex_shows_error()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-ts-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            // Create a test artifact and sign it
            var artifactPath = Path.Combine(tempDir, "test.txt");
            File.WriteAllText(artifactPath, "test content");

            var signResult = await CommandTestHelper.InvokeAsync("sign", artifactPath);
            Assert.DoesNotContain("error", signResult.StdErr, StringComparison.OrdinalIgnoreCase);

            var envelopePath = artifactPath + ".sig.json";
            Assert.True(File.Exists(envelopePath));

            var result = await CommandTestHelper.InvokeAsync(
                "timestamp", envelopePath, "--tsa", "http://localhost/tsa", "--index", "99");

            Assert.Contains("Invalid index", result.StdErr);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task AlreadyTimestamped_shows_error()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-ts-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            // Create a test artifact and sign it
            var artifactPath = Path.Combine(tempDir, "test.txt");
            File.WriteAllText(artifactPath, "test content");

            var signResult = await CommandTestHelper.InvokeAsync("sign", artifactPath);
            Assert.DoesNotContain("error", signResult.StdErr, StringComparison.OrdinalIgnoreCase);

            var envelopePath = artifactPath + ".sig.json";
            Assert.True(File.Exists(envelopePath));

            // Deserialize, add timestampToken, reserialize
            var json = File.ReadAllText(envelopePath);
            var envelope = Sigil.Signing.ArtifactSigner.Deserialize(json);
            var originalEntry = envelope.Signatures[0];
            envelope.Signatures[0] = new Sigil.Signing.SignatureEntry
            {
                KeyId = originalEntry.KeyId,
                Algorithm = originalEntry.Algorithm,
                PublicKey = originalEntry.PublicKey,
                Value = originalEntry.Value,
                Timestamp = originalEntry.Timestamp,
                Label = originalEntry.Label,
                TimestampToken = "dGVzdA=="
            };
            File.WriteAllText(envelopePath, Sigil.Signing.ArtifactSigner.Serialize(envelope));

            var result = await CommandTestHelper.InvokeAsync(
                "timestamp", envelopePath, "--tsa", "http://localhost/tsa", "--index", "0");

            Assert.Contains("already timestamped", result.StdErr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task NoSignatures_shows_error()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-ts-cmd-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var envelopePath = Path.Combine(tempDir, "empty.sig.json");
            File.WriteAllText(envelopePath, """
            {
                "version": "1.0",
                "subject": {
                    "digests": { "sha256": "abc" },
                    "name": "test.txt"
                },
                "signatures": []
            }
            """);

            var result = await CommandTestHelper.InvokeAsync(
                "timestamp", envelopePath, "--tsa", "http://localhost/tsa");

            Assert.Contains("no signatures", result.StdErr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
