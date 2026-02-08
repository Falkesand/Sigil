using Sigil.Attestation;
using Sigil.Timestamping;

namespace Sigil.Core.Tests.Attestation;

public class AttestationTrustAdapterTests
{
    [Fact]
    public void ToVerificationResult_maps_digest_match()
    {
        var attestation = new AttestationVerificationResult
        {
            SubjectDigestMatch = true,
            Signatures = []
        };

        var result = AttestationTrustAdapter.ToVerificationResult(attestation);

        Assert.True(result.ArtifactDigestMatch);
    }

    [Fact]
    public void ToVerificationResult_maps_digest_mismatch()
    {
        var attestation = new AttestationVerificationResult
        {
            SubjectDigestMatch = false,
            Signatures = []
        };

        var result = AttestationTrustAdapter.ToVerificationResult(attestation);

        Assert.False(result.ArtifactDigestMatch);
    }

    [Fact]
    public void ToVerificationResult_maps_signature_fields()
    {
        var attestation = new AttestationVerificationResult
        {
            SubjectDigestMatch = true,
            Signatures =
            [
                new AttestationSignatureResult
                {
                    KeyId = "sha256:aaa",
                    IsValid = true,
                    Algorithm = "ecdsa-p256"
                }
            ]
        };

        var result = AttestationTrustAdapter.ToVerificationResult(attestation);

        Assert.Single(result.Signatures);
        Assert.Equal("sha256:aaa", result.Signatures[0].KeyId);
        Assert.True(result.Signatures[0].IsValid);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void ToVerificationResult_maps_timestamp_info()
    {
        var tsInfo = new TimestampVerificationInfo
        {
            Timestamp = new DateTimeOffset(2026, 2, 9, 12, 0, 0, TimeSpan.Zero),
            IsValid = true
        };

        var attestation = new AttestationVerificationResult
        {
            SubjectDigestMatch = true,
            Signatures =
            [
                new AttestationSignatureResult
                {
                    KeyId = "sha256:bbb",
                    IsValid = true,
                    Algorithm = "ecdsa-p256",
                    TimestampInfo = tsInfo
                }
            ]
        };

        var result = AttestationTrustAdapter.ToVerificationResult(attestation);

        Assert.NotNull(result.Signatures[0].TimestampInfo);
        Assert.True(result.Signatures[0].TimestampInfo!.IsValid);
    }

    [Fact]
    public void ToVerificationResult_maps_error_messages()
    {
        var attestation = new AttestationVerificationResult
        {
            SubjectDigestMatch = true,
            Signatures =
            [
                new AttestationSignatureResult
                {
                    KeyId = "sha256:ccc",
                    IsValid = false,
                    Algorithm = "ecdsa-p256",
                    Error = "Signature verification failed."
                }
            ]
        };

        var result = AttestationTrustAdapter.ToVerificationResult(attestation);

        Assert.False(result.Signatures[0].IsValid);
        Assert.Equal("Signature verification failed.", result.Signatures[0].Error);
    }
}
