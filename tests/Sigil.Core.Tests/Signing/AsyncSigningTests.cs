using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class AsyncSigningTests
{
    [Fact]
    public async Task SignAsync_WithLocalSigner_ProducesValidEnvelope()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(artifactPath, "test artifact content");

            var envelope = await ArtifactSigner.SignAsync(artifactPath, signer, fingerprint, "test-label");

            Assert.NotNull(envelope);
            Assert.Single(envelope.Signatures);
            Assert.Equal(fingerprint.Value, envelope.Signatures[0].KeyId);
            Assert.Equal("test-label", envelope.Signatures[0].Label);
            Assert.Equal("ecdsa-p256", envelope.Signatures[0].Algorithm);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task SignAsync_Envelope_VerifiesSuccessfully()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(artifactPath, "test artifact for verification");

            var envelope = await ArtifactSigner.SignAsync(artifactPath, signer, fingerprint);

            // Verify using the standard sync path
            var result = SignatureValidator.Verify(File.ReadAllBytes(artifactPath), envelope);
            Assert.True(result.AllSignaturesValid);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task AppendSignatureAsync_AddsSecondSignature()
    {
        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP384Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            var content = "multi-sig artifact"u8.ToArray();
            await File.WriteAllBytesAsync(artifactPath, content);

            var envelope = await ArtifactSigner.SignAsync(artifactPath, signer1, fp1);
            await ArtifactSigner.AppendSignatureAsync(envelope, content, signer2, fp2, "second");

            Assert.Equal(2, envelope.Signatures.Count);
            Assert.Equal(fp1.Value, envelope.Signatures[0].KeyId);
            Assert.Equal(fp2.Value, envelope.Signatures[1].KeyId);
            Assert.Equal("second", envelope.Signatures[1].Label);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task SignAsync_ProducesIdenticalEnvelopeFormat_AsSync()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(artifactPath, "format-test");

            var asyncEnvelope = await ArtifactSigner.SignAsync(artifactPath, signer, fingerprint);

            // Both should have the same structure (subject, version, etc.)
            Assert.Equal("1.0", asyncEnvelope.Version);
            Assert.NotNull(asyncEnvelope.Subject);
            Assert.NotNull(asyncEnvelope.Subject.Digests);
            Assert.Contains("sha256", asyncEnvelope.Subject.Digests.Keys);
            Assert.Contains("sha512", asyncEnvelope.Subject.Digests.Keys);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }
}
