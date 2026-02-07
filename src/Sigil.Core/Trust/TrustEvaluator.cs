using System.Globalization;
using Sigil.Signing;

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

        // Rule 2a: Look up key directly in bundle
        var keyEntry = bundle.Keys.FirstOrDefault(k =>
            string.Equals(k.Fingerprint, sig.KeyId, StringComparison.Ordinal));

        if (keyEntry is not null)
        {
            return EvaluateDirectKey(sig, keyEntry, artifactName, now);
        }

        // Rule 2b: Search endorsements
        return EvaluateViaEndorsement(sig, bundle, artifactName, now);
    }

    private static SignatureTrustResult EvaluateDirectKey(
        SignatureVerificationResult sig,
        TrustedKeyEntry keyEntry,
        string? artifactName,
        DateTimeOffset now)
    {
        // Check expiry
        if (IsExpired(keyEntry.NotAfter, now))
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

            // Endorser must not be expired
            if (IsExpired(endorserKey.NotAfter, now))
                continue;

            // Endorsement itself must not be expired
            if (IsExpired(endorsement.NotAfter, now))
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

}
