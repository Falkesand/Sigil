using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class EndorsementEvaluationTests : IDisposable
{
    private readonly ISigner _endorserSigner;
    private readonly KeyFingerprint _endorserFp;
    private readonly ISigner _endorsedSigner;
    private readonly KeyFingerprint _endorsedFp;

    public EndorsementEvaluationTests()
    {
        _endorserSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _endorserFp = KeyFingerprint.Compute(_endorserSigner.PublicKey);
        _endorsedSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _endorsedFp = KeyFingerprint.Compute(_endorsedSigner.PublicKey);
    }

    public void Dispose()
    {
        _endorserSigner.Dispose();
        _endorsedSigner.Dispose();
    }

    [Fact]
    public void TrustedViaEndorsement_when_endorser_in_bundle()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry { Fingerprint = _endorserFp.Value, DisplayName = "Endorser" }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFp.Value,
                    Endorsed = _endorsedFp.Value,
                    Statement = "Trusted CI key",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var verification = CreateVerificationResult(_endorsedFp.Value, valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.TrustedViaEndorsement, result.Signatures[0].Decision);
        Assert.Contains("Endorser", result.Signatures[0].Reason!);
    }

    [Fact]
    public void Untrusted_when_endorser_not_in_bundle()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys = [],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFp.Value,
                    Endorsed = _endorsedFp.Value,
                    Statement = "Orphaned endorsement",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var verification = CreateVerificationResult(_endorsedFp.Value, valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Untrusted_when_endorser_expired()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = _endorserFp.Value,
                    DisplayName = "Endorser",
                    NotAfter = "2020-01-01T00:00:00Z"
                }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFp.Value,
                    Endorsed = _endorsedFp.Value,
                    Statement = "Expired endorser",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var verification = CreateVerificationResult(_endorsedFp.Value, valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Untrusted_when_endorsement_expired()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry { Fingerprint = _endorserFp.Value, DisplayName = "Endorser" }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFp.Value,
                    Endorsed = _endorsedFp.Value,
                    Statement = "Expired endorsement",
                    NotAfter = "2020-01-01T00:00:00Z",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var verification = CreateVerificationResult(_endorsedFp.Value, valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Non_transitive_endorsement()
    {
        // A endorses B, B endorses C — C should NOT be trusted
        using var cSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var cFp = KeyFingerprint.Compute(cSigner.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry { Fingerprint = _endorserFp.Value, DisplayName = "A" }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFp.Value,
                    Endorsed = _endorsedFp.Value,
                    Statement = "A endorses B",
                    Timestamp = "2026-02-08T12:00:00Z"
                },
                new Endorsement
                {
                    Endorser = _endorsedFp.Value,
                    Endorsed = cFp.Value,
                    Statement = "B endorses C",
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var verification = CreateVerificationResult(cFp.Value, valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Endorsement_scope_restricts_trust()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry { Fingerprint = _endorserFp.Value, DisplayName = "Endorser" }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFp.Value,
                    Endorsed = _endorsedFp.Value,
                    Statement = "Only for tarballs",
                    Scopes = new TrustScopes { NamePatterns = ["*.tar.gz"] },
                    Timestamp = "2026-02-08T12:00:00Z"
                }
            ]
        };

        var verification = CreateVerificationResult(_endorsedFp.Value, valid: true);

        // Matching scope
        var matchResult = TrustEvaluator.Evaluate(verification, bundle, "release.tar.gz");
        Assert.Equal(TrustDecision.TrustedViaEndorsement, matchResult.Signatures[0].Decision);

        // Non-matching scope
        var mismatchResult = TrustEvaluator.Evaluate(verification, bundle, "release.zip");
        Assert.Equal(TrustDecision.Untrusted, mismatchResult.Signatures[0].Decision);
    }

    private static VerificationResult CreateVerificationResult(string keyId, bool valid) =>
        new()
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = keyId,
                    IsValid = valid,
                    Algorithm = "ecdsa-p256"
                }
            ]
        };
}
