using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Cli.Tests.Commands;

public class VerifyTimeTravelTests : IDisposable
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _tempDir;
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;
    private readonly string _artifactPath;
    private readonly string _signaturePath;

    public VerifyTimeTravelTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-tt-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);

        _artifactPath = Path.Combine(_tempDir, "artifact.txt");
        File.WriteAllText(_artifactPath, "test artifact content");

        var envelope = ArtifactSigner.Sign(_artifactPath, _signer, _fingerprint);
        var json = ArtifactSigner.Serialize(envelope);
        _signaturePath = _artifactPath + ".sig.json";
        File.WriteAllText(_signaturePath, json);
    }

    public void Dispose()
    {
        _signer.Dispose();
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private string CreateTrustBundle(string? notAfter = null, RevocationEntry? revocation = null)
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = _fingerprint.Value,
                    DisplayName = "Test Key",
                    NotAfter = notAfter
                }
            ]
        };

        if (revocation is not null)
            bundle.Revocations.Add(revocation);

        var path = Path.Combine(_tempDir, $"trust-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(bundle, s_jsonOptions));
        return path;
    }

    // -----------------------------------------------------------------------
    // Tests 1-8: Core --at behavior on the verify command
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Verify_at_before_expiry_shows_trusted()
    {
        var bundlePath = CreateTrustBundle(notAfter: "2028-01-01T00:00:00Z");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2027-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("TRUSTED", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_after_expiry_shows_expired()
    {
        var bundlePath = CreateTrustBundle(notAfter: "2026-01-01T00:00:00Z");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2027-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("EXPIRED", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_before_revocation_shows_trusted()
    {
        var bundlePath = CreateTrustBundle(revocation: new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z",
            Reason = "Compromised"
        });

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2026-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("TRUSTED", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_after_revocation_shows_revoked()
    {
        var bundlePath = CreateTrustBundle(revocation: new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z",
            Reason = "Compromised"
        });

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2027-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("REVOKED", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_invalid_date_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--at", "not-a-date");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Invalid date format", result.StdErr);
    }

    [Fact]
    public async Task Verify_at_date_only_parses_as_midnight_utc()
    {
        var bundlePath = CreateTrustBundle(notAfter: "2028-01-01T00:00:00Z");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2027-06-15");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("2027-06-15", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_without_trust_bundle_just_verifies_crypto()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--at", "2027-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_output_includes_evaluation_time_annotation()
    {
        var bundlePath = CreateTrustBundle(notAfter: "2028-01-01T00:00:00Z");

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2025-06-15T14:30:00Z");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Evaluating trust as of:", result.StdOut);
    }

    // -----------------------------------------------------------------------
    // Tests 9-10: Endorsement path with --at
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Verify_at_with_endorsement_before_expiry_shows_trusted()
    {
        // Create an endorser key that is directly trusted
        using var endorserSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var endorserFp = KeyFingerprint.Compute(endorserSigner.PublicKey);

        // Build bundle: endorser is in Keys, signing key is NOT in Keys,
        // but is endorsed by the endorser with a notAfter in the future.
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "endorsement-test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = endorserFp.Value,
                    DisplayName = "Endorser Key"
                }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = endorserFp.Value,
                    Endorsed = _fingerprint.Value,
                    Statement = "Endorsed for testing",
                    NotAfter = "2028-01-01T00:00:00Z",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var bundlePath = Path.Combine(_tempDir, $"trust-endorse-{Guid.NewGuid():N}.json");
        File.WriteAllText(bundlePath, JsonSerializer.Serialize(bundle, s_jsonOptions));

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2027-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("TRUSTED", result.StdOut);
    }

    [Fact]
    public async Task Verify_at_with_endorsement_after_expiry_shows_untrusted()
    {
        using var endorserSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var endorserFp = KeyFingerprint.Compute(endorserSigner.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "endorsement-test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = endorserFp.Value,
                    DisplayName = "Endorser Key"
                }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = endorserFp.Value,
                    Endorsed = _fingerprint.Value,
                    Statement = "Endorsed for testing",
                    NotAfter = "2026-06-01T00:00:00Z",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var bundlePath = Path.Combine(_tempDir, $"trust-endorse-{Guid.NewGuid():N}.json");
        File.WriteAllText(bundlePath, JsonSerializer.Serialize(bundle, s_jsonOptions));

        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2027-01-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("[UNTRUSTED]", result.StdOut);
        Assert.DoesNotContain("[TRUSTED]", result.StdOut);
    }

    // -----------------------------------------------------------------------
    // Tests 11-15: Cross-command spot checks (--at parsing wired in correctly)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Verify_attestation_at_invalid_date_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-attestation", _artifactPath, "--at", "not-a-date");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Invalid date format", result.StdErr);
    }

    [Fact]
    public async Task Verify_manifest_at_invalid_date_shows_error()
    {
        var dummyManifest = Path.Combine(_tempDir, "dummy-manifest.sig.json");
        File.WriteAllText(dummyManifest, "{}"); // content irrelevant; --at parsing runs first

        var result = await CommandTestHelper.InvokeAsync(
            "verify-manifest", dummyManifest, "--at", "not-a-date");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Invalid date format", result.StdErr);
    }

    [Fact]
    public async Task Verify_archive_at_invalid_date_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-archive", "dummy.zip", "--at", "not-a-date");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Invalid date format", result.StdErr);
    }

    [Fact]
    public async Task Verify_pe_at_invalid_date_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-pe", "dummy.exe", "--at", "not-a-date");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Invalid date format", result.StdErr);
    }

    [Fact]
    public async Task Verify_image_at_invalid_date_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-image", "dummy:latest", "--at", "not-a-date");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Invalid date format", result.StdErr);
    }

    // -----------------------------------------------------------------------
    // Test 16: Both revoked and expired, eval before both shows trusted
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Verify_at_before_revocation_and_expiry_shows_trusted()
    {
        var bundlePath = CreateTrustBundle(
            notAfter: "2027-01-01T00:00:00Z",
            revocation: new RevocationEntry
            {
                Fingerprint = _fingerprint.Value,
                RevokedAt = "2027-06-01T00:00:00Z",
                Reason = "Compromised later"
            });

        // Evaluate at a time before both expiry and revocation
        var result = await CommandTestHelper.InvokeAsync(
            "verify", _artifactPath, "--trust-bundle", bundlePath, "--at", "2026-06-01");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("TRUSTED", result.StdOut);
        Assert.DoesNotContain("EXPIRED", result.StdOut);
        Assert.DoesNotContain("REVOKED", result.StdOut);
    }
}
