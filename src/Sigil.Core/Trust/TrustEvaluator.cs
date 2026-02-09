using System.Globalization;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Trust;

/// <summary>
/// Core trust decision engine. Evaluates crypto-verified signatures against a trust bundle.
/// Layer 3: trust decisions — sits above crypto verification (Layer 2).
/// </summary>
public static class TrustEvaluator
{
    /// <summary>
    /// Evaluates trust for all signatures in a verification result against a trust bundle.
    /// </summary>
    public static TrustEvaluationResult Evaluate(
        VerificationResult verification,
        TrustBundle bundle,
        string? artifactName,
        DateTimeOffset? evaluationTime = null)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ArgumentNullException.ThrowIfNull(bundle);

        var now = evaluationTime ?? DateTimeOffset.UtcNow;

        var results = new List<SignatureTrustResult>(verification.Signatures.Count);

        foreach (var sig in verification.Signatures)
        {
            results.Add(EvaluateSignature(sig, bundle, artifactName, now));
        }

        return new TrustEvaluationResult { Signatures = results };
    }

    private static SignatureTrustResult EvaluateSignature(
        SignatureVerificationResult sig,
        TrustBundle bundle,
        string? artifactName,
        DateTimeOffset now)
    {
        // Rule 1: Crypto failure trumps trust
        if (!sig.IsValid)
        {
            return new SignatureTrustResult
            {
                KeyId = sig.KeyId,
                Decision = TrustDecision.Untrusted,
                Reason = "Cryptographic verification failed."
            };
        }

        // Rule 2: Check if key is revoked (applies to both direct and endorsement paths)
        var revocation = bundle.Revocations.FirstOrDefault(r =>
            string.Equals(r.Fingerprint, sig.KeyId, StringComparison.Ordinal));

        if (revocation is not null)
        {
            var reason = revocation.Reason is not null
                ? $"Key revoked on {revocation.RevokedAt}: {revocation.Reason}"
                : $"Key revoked on {revocation.RevokedAt}.";

            return new SignatureTrustResult
            {
                KeyId = sig.KeyId,
                Decision = TrustDecision.Revoked,
                Reason = reason
            };
        }

        // Rule 3a: Look up key directly in bundle
        var keyEntry = bundle.Keys.FirstOrDefault(k =>
            string.Equals(k.Fingerprint, sig.KeyId, StringComparison.Ordinal));

        if (keyEntry is not null)
        {
            return EvaluateDirectKey(sig, keyEntry, artifactName, now);
        }

        // Rule 3b: Search endorsements
        return EvaluateViaEndorsement(sig, bundle, artifactName, now);
    }

    private static SignatureTrustResult EvaluateDirectKey(
        SignatureVerificationResult sig,
        TrustedKeyEntry keyEntry,
        string? artifactName,
        DateTimeOffset now)
    {
        // Check expiry — a valid timestamp before expiry overrides the expired decision
        if (IsExpired(keyEntry.NotAfter, now) &&
            !IsTimestampBeforeExpiry(sig.TimestampInfo, keyEntry.NotAfter))
        {
            return new SignatureTrustResult
            {
                KeyId = sig.KeyId,
                Decision = TrustDecision.Expired,
                DisplayName = keyEntry.DisplayName,
                Reason = $"Key expired (notAfter: {keyEntry.NotAfter})."
            };
        }

        // Check scopes
        if (!ScopeMatcher.Matches(keyEntry.Scopes, artifactName, sig.Label, sig.Algorithm))
        {
            return new SignatureTrustResult
            {
                KeyId = sig.KeyId,
                Decision = TrustDecision.ScopeMismatch,
                DisplayName = keyEntry.DisplayName,
                Reason = "Key scope does not match artifact."
            };
        }

        return new SignatureTrustResult
        {
            KeyId = sig.KeyId,
            Decision = TrustDecision.Trusted,
            DisplayName = keyEntry.DisplayName,
            Reason = "Key is directly trusted."
        };
    }

    private static SignatureTrustResult EvaluateViaEndorsement(
        SignatureVerificationResult sig,
        TrustBundle bundle,
        string? artifactName,
        DateTimeOffset now)
    {
        // Find endorsements where the endorsed key matches this signature's keyId
        foreach (var endorsement in bundle.Endorsements)
        {
            if (!string.Equals(endorsement.Endorsed, sig.KeyId, StringComparison.Ordinal))
                continue;

            // The endorser must be directly in bundle.keys (non-transitive)
            var endorserKey = bundle.Keys.FirstOrDefault(k =>
                string.Equals(k.Fingerprint, endorsement.Endorser, StringComparison.Ordinal));

            if (endorserKey is null)
                continue;

            // Check if endorser is revoked
            var endorserRevoked = bundle.Revocations.Any(r =>
                string.Equals(r.Fingerprint, endorsement.Endorser, StringComparison.Ordinal));
            if (endorserRevoked)
                continue;

            // Endorser must not be expired (unless timestamp proves signature predates expiry)
            if (IsExpired(endorserKey.NotAfter, now) &&
                !IsTimestampBeforeExpiry(sig.TimestampInfo, endorserKey.NotAfter))
                continue;

            // Endorsement itself must not be expired (unless timestamp proves signature predates expiry)
            if (IsExpired(endorsement.NotAfter, now) &&
                !IsTimestampBeforeExpiry(sig.TimestampInfo, endorsement.NotAfter))
                continue;

            // Check scope intersection (endorsement scopes restrict further)
            var effectiveScopes = ScopeMatcher.Intersect(endorserKey.Scopes, endorsement.Scopes);
            if (!ScopeMatcher.Matches(effectiveScopes, artifactName, sig.Label, sig.Algorithm))
                continue;

            return new SignatureTrustResult
            {
                KeyId = sig.KeyId,
                Decision = TrustDecision.TrustedViaEndorsement,
                Reason = $"Endorsed by {endorserKey.DisplayName ?? endorsement.Endorser}."
            };
        }

        return new SignatureTrustResult
        {
            KeyId = sig.KeyId,
            Decision = TrustDecision.Untrusted,
            Reason = "Key not found in trust bundle."
        };
    }

    private static bool IsExpired(string? notAfter, DateTimeOffset now)
    {
        if (notAfter is null)
            return false;

        if (DateTimeOffset.TryParse(notAfter, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var expiry))
        {
            return now >= expiry;
        }

        return false;
    }

    private static bool IsTimestampBeforeExpiry(TimestampVerificationInfo? tsInfo, string? notAfter)
    {
        if (tsInfo is not { IsValid: true })
            return false;
        if (notAfter is null)
            return false;
        if (!DateTimeOffset.TryParse(notAfter, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var expiry))
            return false;
        return tsInfo.Timestamp < expiry;
    }
}
