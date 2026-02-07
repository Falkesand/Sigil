using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Signing;

/// <summary>
/// Result of verifying a single signature entry.
/// </summary>
public sealed class SignatureVerificationResult
{
    public required string KeyId { get; init; }
    public required bool IsValid { get; init; }
    public string? Label { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Result of verifying all signatures in an envelope.
/// </summary>
public sealed class VerificationResult
{
    public required bool ArtifactDigestMatch { get; init; }
    public required IReadOnlyList<SignatureVerificationResult> Signatures { get; init; }

    public bool AllSignaturesValid => ArtifactDigestMatch && Signatures.All(s => s.IsValid);
    public bool AnySignatureValid => ArtifactDigestMatch && Signatures.Any(s => s.IsValid);
}

/// <summary>
/// Cryptographic verification of signature envelopes.
/// Layer 2: pure math — no trust decisions.
/// Public keys are extracted from the envelope itself — no external key store needed.
/// </summary>
public static class SignatureValidator
{
    /// <summary>
    /// Verifies all signatures in an envelope against an artifact file.
    /// </summary>
    public static VerificationResult Verify(
        string artifactPath,
        SignatureEnvelope envelope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentNullException.ThrowIfNull(envelope);

        if (!File.Exists(artifactPath))
            throw new FileNotFoundException("Artifact not found.", artifactPath);

        var fileBytes = File.ReadAllBytes(artifactPath);
        return Verify(fileBytes, envelope);
    }

    /// <summary>
    /// Verifies all signatures in an envelope against artifact bytes.
    /// </summary>
    public static VerificationResult Verify(
        byte[] artifactBytes,
        SignatureEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(artifactBytes);
        ArgumentNullException.ThrowIfNull(envelope);

        // Step 1: Verify artifact digests match
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(artifactBytes);

        bool digestMatch = true;
        if (envelope.Subject.Digests.TryGetValue("sha256", out var expectedSha256))
            digestMatch &= string.Equals(sha256, expectedSha256, StringComparison.OrdinalIgnoreCase);
        if (envelope.Subject.Digests.TryGetValue("sha512", out var expectedSha512))
            digestMatch &= string.Equals(sha512, expectedSha512, StringComparison.OrdinalIgnoreCase);

        // Step 2: Verify each signature using the embedded public key
        var sigResults = new List<SignatureVerificationResult>();

        foreach (var sig in envelope.Signatures)
        {
            sigResults.Add(VerifySingleSignature(sig, envelope.Subject, artifactBytes, envelope.Version));
        }

        return new VerificationResult
        {
            ArtifactDigestMatch = digestMatch,
            Signatures = sigResults
        };
    }

    private static SignatureVerificationResult VerifySingleSignature(
        SignatureEntry sig,
        SubjectDescriptor subject,
        byte[] artifactBytes,
        string version)
    {
        try
        {
            if (string.IsNullOrEmpty(sig.PublicKey))
            {
                return new SignatureVerificationResult
                {
                    KeyId = sig.KeyId,
                    IsValid = false,
                    Label = sig.Label,
                    Error = "Public key not found in signature entry."
                };
            }

            // Decode the embedded public key
            var spkiBytes = Convert.FromBase64String(sig.PublicKey);

            // Verify fingerprint matches keyId (integrity check)
            var computedFingerprint = KeyFingerprint.Compute(spkiBytes);
            if (computedFingerprint.Value != sig.KeyId)
            {
                return new SignatureVerificationResult
                {
                    KeyId = sig.KeyId,
                    IsValid = false,
                    Label = sig.Label,
                    Error = "Public key fingerprint does not match keyId."
                };
            }

            // Rebuild the signing payload using the entry's metadata
            var signingPayload = ArtifactSigner.BuildSigningPayload(
                subject, artifactBytes, version,
                sig.KeyId, sig.Algorithm, sig.Timestamp, sig.Label);

            // Create verifier from the embedded SPKI and verify
            using var verifier = VerifierFactory.CreateFromPublicKey(spkiBytes, sig.Algorithm);
            var signatureBytes = Convert.FromBase64String(sig.Value);
            var isValid = verifier.Verify(signingPayload, signatureBytes);

            return new SignatureVerificationResult
            {
                KeyId = sig.KeyId,
                IsValid = isValid,
                Label = sig.Label,
                Error = isValid ? null : "Signature verification failed."
            };
        }
        catch (Exception ex)
        {
            return new SignatureVerificationResult
            {
                KeyId = sig.KeyId,
                IsValid = false,
                Label = sig.Label,
                Error = ex.Message
            };
        }
    }
}
