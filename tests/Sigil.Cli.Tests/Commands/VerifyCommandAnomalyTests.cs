using System.Text.Json;
using Sigil.Anomaly;
using Sigil.Signing;

namespace Sigil.Cli.Tests.Commands;

public class VerifyCommandAnomalyTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public VerifyCommandAnomalyTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-anomaly-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "anomaly test artifact content");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Verify_with_anomaly_and_baseline_detects_unknown_signer()
    {
        // Sign the artifact (uses ephemeral key A)
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Create a baseline with a DIFFERENT signer key (not the one that signed the artifact)
        var baseline = new BaselineModel
        {
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
            SampleCount = 1,
            Signers = new Dictionary<string, SignerInfo>
            {
                ["sha256:0000000000000000000000000000000000000000000000000000000000000000"] = new SignerInfo
                {
                    Count = 5,
                    Algorithm = "ecdsa-p256",
                    LastSeen = DateTimeOffset.UtcNow
                }
            },
            Algorithms = ["ecdsa-p256"],
            SigningHours = Enumerable.Range(0, 24).ToList()
        };
        var baselinePath = Path.Combine(_tempDir, ".sigil.baseline.json");
        File.WriteAllText(baselinePath, BaselineSerializer.Serialize(baseline));

        // Verify with --anomaly
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath, "--anomaly");

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("Anomaly Detection Report", result.StdOut);
        Assert.Contains("not in the baseline", result.StdOut);
    }

    [Fact]
    public async Task Verify_with_anomaly_and_no_baseline_prints_warning()
    {
        // Sign the artifact
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Do NOT create a baseline file
        // Verify with --anomaly
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath, "--anomaly");

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("No baseline found", result.StdOut);
    }

    [Fact]
    public async Task Verify_with_anomaly_and_known_signer_shows_no_anomalies()
    {
        // Sign the artifact
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Use baseline learn to create a baseline from the signature
        await CommandTestHelper.InvokeAsync("baseline", "learn", "--scan", _tempDir);

        // Verify with --anomaly (baseline at default location)
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath, "--anomaly");

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("No anomalies detected", result.StdOut);
    }

    [Fact]
    public async Task Verify_with_anomaly_and_custom_baseline_loads_path()
    {
        // Sign the artifact
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Use baseline learn with custom output path
        var customBaseline = Path.Combine(_tempDir, "custom-baseline.json");
        await CommandTestHelper.InvokeAsync("baseline", "learn", "--scan", _tempDir, "--output", customBaseline);

        // Verify with --anomaly --baseline pointing to custom path
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath, "--anomaly", "--baseline", customBaseline);

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.Contains("No anomalies detected", result.StdOut);
    }

    [Fact]
    public async Task Verify_without_anomaly_does_not_run_detection()
    {
        // Sign the artifact
        await CommandTestHelper.InvokeAsync("sign", _artifactPath);

        // Create a baseline that would trigger anomalies (wrong signer)
        var baseline = new BaselineModel
        {
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
            SampleCount = 1,
            Signers = new Dictionary<string, SignerInfo>
            {
                ["sha256:0000000000000000000000000000000000000000000000000000000000000000"] = new SignerInfo
                {
                    Count = 5,
                    Algorithm = "ecdsa-p256",
                    LastSeen = DateTimeOffset.UtcNow
                }
            },
            Algorithms = ["ecdsa-p256"],
            SigningHours = Enumerable.Range(0, 24).ToList()
        };
        var baselinePath = Path.Combine(_tempDir, ".sigil.baseline.json");
        File.WriteAllText(baselinePath, BaselineSerializer.Serialize(baseline));

        // Verify WITHOUT --anomaly flag
        var result = await CommandTestHelper.InvokeAsync("verify", _artifactPath);

        Assert.Contains("VERIFIED", result.StdOut);
        Assert.DoesNotContain("anomal", result.StdOut, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("anomal", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }
}
