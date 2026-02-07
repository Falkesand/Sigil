using Secure.Sbom.Crypto;
using Secure.Sbom.Keys;

namespace Secure.Sbom.Signing;

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
/// </summary>
public static class SignatureValidator
{
    /// <summary>
    /// Verifies all signatures in an envelope against an artifact file.
    /// </summary>
    public static VerificationResult Verify(
        string artifactPath,
        SignatureEnvelope envelope,
        KeyStore keyStore)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(keyStore);

        if (!File.Exists(artifactPath))
            throw new FileNotFoundException("Artifact not found.", artifactPath);

        var fileBytes = File.ReadAllBytes(artifactPath);
        return Verify(fileBytes, envelope, keyStore);
    }

    /// <summary>
    /// Verifies all signatures in an envelope against artifact bytes.
    /// </summary>
    public static VerificationResult Verify(
        byte[] artifactBytes,
        SignatureEnvelope envelope,
        KeyStore keyStore)
    {
        ArgumentNullException.ThrowIfNull(artifactBytes);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(keyStore);

        // Step 1: Verify artifact digests match
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(artifactBytes);

        bool digestMatch = true;
        if (envelope.Subject.Digests.TryGetValue("sha256", out var expectedSha256))
            digestMatch &= string.Equals(sha256, expectedSha256, StringComparison.OrdinalIgnoreCase);
        if (envelope.Subject.Digests.TryGetValue("sha512", out var expectedSha512))
            digestMatch &= string.Equals(sha512, expectedSha512, StringComparison.OrdinalIgnoreCase);

        // Step 2: Verify each signature
        var sigResults = new List<SignatureVerificationResult>();
        var signingPayload = ArtifactSigner.BuildSigningPayload(envelope.Subject, artifactBytes);

        foreach (var sig in envelope.Signatures)
        {
            sigResults.Add(VerifySingleSignature(sig, signingPayload, keyStore));
        }

        return new VerificationResult
        {
            ArtifactDigestMatch = digestMatch,
            Signatures = sigResults
        };
    }

    private static SignatureVerificationResult VerifySingleSignature(
        SignatureEntry sig,
        byte[] signingPayload,
        KeyStore keyStore)
    {
        try
        {
            var fingerprint = KeyFingerprint.Parse(sig.KeyId);

            if (!keyStore.KeyExists(fingerprint))
            {
                return new SignatureVerificationResult
                {
                    KeyId = sig.KeyId,
                    IsValid = false,
                    Label = sig.Label,
                    Error = "Public key not found in key store."
                };
            }

            var verifier = keyStore.LoadVerifier(fingerprint);
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
