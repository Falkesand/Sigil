using System.Security.Cryptography;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Policy;
using Sigil.Signing;
using Sigil.Transparency.Remote;
using Xunit;

namespace Sigil.LogServer.Tests;

public class EndToEndTransparencyTests : IAsyncLifetime
{
    private TestLogServer _server = null!;
    private string _tempDir = null!;

    public async Task InitializeAsync()
    {
        _server = await TestLogServer.CreateAsync();
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-e2e-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public async Task DisposeAsync()
    {
        await _server.DisposeAsync();
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task Sign_SubmitToLogServer_Verify_WithLoggedPolicy_Passes()
    {
        // 1. Create and sign an artifact
        var artifactPath = Path.Combine(_tempDir, "artifact.txt");
        File.WriteAllText(artifactPath, "end-to-end test content");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(artifactPath, signer, fingerprint, "e2e-test");

        // 2. Submit to LogServer via SigilLogClient
        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);
        var lastEntry = envelope.Signatures[^1];
        var submitResult = await LogSubmitter.SubmitAsync(lastEntry, envelope.Subject, logClient);

        Assert.True(submitResult.IsSuccess, submitResult.IsSuccess ? "OK" : $"Log submission failed: {submitResult.ErrorMessage}");
        envelope.Signatures[^1] = submitResult.Value;

        // 3. Verify the artifact
        var artifactBytes = File.ReadAllBytes(artifactPath);
        var verification = SignatureValidator.Verify(artifactBytes, envelope);
        Assert.True(verification.AnySignatureValid);

        // 4. Evaluate "require": "logged" policy
        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "logged" }]
        };

        var context = new PolicyContext
        {
            Verification = verification,
            Envelope = envelope,
            ArtifactName = "artifact.txt"
        };

        var policyResult = PolicyEvaluator.Evaluate(policy, context);
        Assert.True(policyResult.AllPassed, "Logged policy should pass: " +
            string.Join("; ", policyResult.Results.Where(r => !r.Passed).Select(r => r.Reason)));
    }

    [Fact]
    public async Task Sign_SubmitToLogServer_Verify_WithLoggedPolicyAndPublicKey_Passes()
    {
        // 1. Create and sign an artifact
        var artifactPath = Path.Combine(_tempDir, "artifact2.txt");
        File.WriteAllText(artifactPath, "end-to-end test with public key verification");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(artifactPath, signer, fingerprint);

        // 2. Submit to LogServer
        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);
        var submitResult = await LogSubmitter.SubmitAsync(
            envelope.Signatures[^1], envelope.Subject, logClient);

        Assert.True(submitResult.IsSuccess);
        envelope.Signatures[^1] = submitResult.Value;

        // 3. Verify the artifact
        var artifactBytes = File.ReadAllBytes(artifactPath);
        var verification = SignatureValidator.Verify(artifactBytes, envelope);

        // 4. Evaluate "require": "logged" with logPublicKey
        var logPublicKeyBase64 = Convert.ToBase64String(_server.Signer.PublicKeySpki);
        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule
            {
                Require = "logged",
                LogPublicKey = logPublicKeyBase64
            }]
        };

        var context = new PolicyContext
        {
            Verification = verification,
            Envelope = envelope,
            ArtifactName = "artifact2.txt"
        };

        var policyResult = PolicyEvaluator.Evaluate(policy, context);
        Assert.True(policyResult.AllPassed, "Logged policy with public key should pass: " +
            string.Join("; ", policyResult.Results.Where(r => !r.Passed).Select(r => r.Reason)));
    }

    [Fact]
    public void Unsigned_Artifact_FailsLoggedPolicy()
    {
        // Create an envelope without transparency data
        var verification = new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = "sha256:abc123",
                    IsValid = true,
                    Algorithm = "ecdsa-p256"
                }
            ]
        };

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.txt",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:abc123",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "base64key",
                    Value = "base64sig",
                    Timestamp = DateTime.UtcNow.ToString("o")
                }
            ]
        };

        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule { Require = "logged" }]
        };

        var context = new PolicyContext
        {
            Verification = verification,
            Envelope = envelope,
            ArtifactName = "test.txt"
        };

        var result = PolicyEvaluator.Evaluate(policy, context);
        Assert.False(result.AllPassed);
    }

    [Fact]
    public async Task Sign_SubmitToLogServer_InclusionProof_IsVerifiable()
    {
        // Sign and submit
        var artifactPath = Path.Combine(_tempDir, "proof-test.txt");
        File.WriteAllText(artifactPath, "proof verification test");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(artifactPath, signer, fingerprint);

        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);
        var submitResult = await LogSubmitter.SubmitAsync(
            envelope.Signatures[^1], envelope.Subject, logClient);

        Assert.True(submitResult.IsSuccess);

        var loggedEntry = submitResult.Value;

        // Verify the inclusion proof is present and valid
        Assert.NotNull(loggedEntry.TransparencyLogUrl);
        Assert.NotNull(loggedEntry.TransparencyLogIndex);
        Assert.NotNull(loggedEntry.TransparencySignedCheckpoint);
        Assert.NotNull(loggedEntry.TransparencyInclusionProof);

        // Fetch the inclusion proof from the server independently
        var proofResult = await logClient.GetInclusionProofAsync(loggedEntry.TransparencyLogIndex!.Value - 1);
        Assert.True(proofResult.IsSuccess);
    }

    [Fact]
    public async Task Sign_SubmitToLogServer_PublicKey_IsRetrievable()
    {
        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);

        var keyResult = await logClient.GetPublicKeyAsync();
        Assert.True(keyResult.IsSuccess);

        var keyBase64 = keyResult.Value;
        var keyBytes = Convert.FromBase64String(keyBase64);

        // Verify it's a valid SPKI
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
    }

    [Fact]
    public async Task Sign_SubmitToLogServer_Checkpoint_IsVerifiable()
    {
        // Submit an entry first to create a checkpoint
        var artifactPath = Path.Combine(_tempDir, "checkpoint-test.txt");
        File.WriteAllText(artifactPath, "checkpoint verification test");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(artifactPath, signer, fingerprint);

        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);
        var submitResult = await LogSubmitter.SubmitAsync(
            envelope.Signatures[^1], envelope.Subject, logClient);

        Assert.True(submitResult.IsSuccess);

        // Get checkpoint and verify it's signed
        var checkpointResult = await logClient.GetCheckpointAsync();
        Assert.True(checkpointResult.IsSuccess);
        Assert.True(checkpointResult.Value.TreeSize > 0);
        Assert.NotEmpty(checkpointResult.Value.RootHash);
        Assert.NotEmpty(checkpointResult.Value.Signature);
    }

    [Fact]
    public async Task Multiple_Submissions_ProduceConsistencyProof()
    {
        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);

        // Submit 3 entries
        for (int i = 0; i < 3; i++)
        {
            var path = Path.Combine(_tempDir, $"consistency-{i}.txt");
            File.WriteAllText(path, $"consistency test content {i}");

            using var s = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
            var fp = KeyFingerprint.Compute(s.PublicKey);
            var env = ArtifactSigner.Sign(path, s, fp);

            var result = await LogSubmitter.SubmitAsync(env.Signatures[^1], env.Subject, logClient);
            Assert.True(result.IsSuccess, result.IsSuccess ? "OK" : $"Submission {i} failed: {result.ErrorMessage}");
        }

        // Verify checkpoint reflects all entries
        var checkpoint = await logClient.GetCheckpointAsync();
        Assert.True(checkpoint.IsSuccess);
        Assert.True(checkpoint.Value.TreeSize >= 3);
    }

    [Fact]
    public async Task Duplicate_Submission_Returns_DuplicateError()
    {
        var artifactPath = Path.Combine(_tempDir, "duplicate-test.txt");
        File.WriteAllText(artifactPath, "duplicate test");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(artifactPath, signer, fingerprint);

        var logUrl = _server.Client.BaseAddress!.ToString().TrimEnd('/');
        using var logClient = new SigilLogClient(logUrl, _server.ApiKey, _server.Client);

        // First submission succeeds
        var result1 = await logClient.AppendAsync(envelope.Signatures[^1], envelope.Subject);
        Assert.True(result1.IsSuccess);

        // Second submission returns duplicate
        var result2 = await logClient.AppendAsync(envelope.Signatures[^1], envelope.Subject);
        Assert.False(result2.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.DuplicateEntry, result2.ErrorKind);
    }
}
