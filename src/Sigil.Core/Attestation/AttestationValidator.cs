using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Timestamping;

namespace Sigil.Attestation;

/// <summary>
/// Cryptographic verification of DSSE attestation envelopes.
/// Verifies PAE-based signatures and subject digest matching.
/// </summary>
public static class AttestationValidator
{
    /// <summary>
    /// Verifies a DSSE attestation envelope against an artifact file.
    /// </summary>
    public static AttestationVerificationResult Verify(
        string artifactPath,
        DsseEnvelope envelope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentNullException.ThrowIfNull(envelope);

        if (!File.Exists(artifactPath))
            throw new FileNotFoundException("Artifact not found.", artifactPath);

        var fileBytes = File.ReadAllBytes(artifactPath);
        return Verify(fileBytes, envelope);
    }

    /// <summary>
    /// Verifies a DSSE attestation envelope against artifact bytes.
    /// </summary>
    public static AttestationVerificationResult Verify(
        byte[] artifactBytes,
        DsseEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(artifactBytes);
        ArgumentNullException.ThrowIfNull(envelope);

        // Step 1: Extract statement and verify subject digest
        var statementResult = AttestationCreator.ExtractStatement(envelope);
        if (!statementResult.IsSuccess)
        {
            return new AttestationVerificationResult
            {
                SubjectDigestMatch = false,
                Signatures = [],
                Statement = null
            };
        }

        var statement = statementResult.Value;
        var digestMatch = VerifySubjectDigest(artifactBytes, statement);

        // Step 2: Verify each DSSE signature
        var sigResults = new List<AttestationSignatureResult>();
        foreach (var sig in envelope.Signatures)
        {
            sigResults.Add(VerifySingleSignature(sig, envelope.PayloadType, envelope.Payload));
        }

        return new AttestationVerificationResult
        {
            SubjectDigestMatch = digestMatch,
            Signatures = sigResults,
            Statement = statement
        };
    }

    private static bool VerifySubjectDigest(byte[] artifactBytes, InTotoStatement statement)
    {
        if (statement.Subject.Count == 0)
            return false;

        var sha256 = HashAlgorithms.Sha256Hex(artifactBytes);

        // Check if any subject matches the artifact digest
        foreach (var subject in statement.Subject)
        {
            if (subject.Digest.TryGetValue("sha256", out var expectedSha256)
                && string.Equals(sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static AttestationSignatureResult VerifySingleSignature(
        DsseSignature sig,
        string payloadType,
        string base64Payload)
    {
        try
        {
            if (string.IsNullOrEmpty(sig.PublicKey))
            {
                return new AttestationSignatureResult
                {
                    KeyId = sig.KeyId,
                    IsValid = false,
                    Algorithm = sig.Algorithm,
                    Error = "Public key not found in signature entry."
                };
            }

            // Decode the embedded public key
            var spkiBytes = Convert.FromBase64String(sig.PublicKey);

            // Verify fingerprint matches keyId
            var computedFingerprint = KeyFingerprint.Compute(spkiBytes);
            if (computedFingerprint.Value != sig.KeyId)
            {
                return new AttestationSignatureResult
                {
                    KeyId = sig.KeyId,
                    IsValid = false,
                    Algorithm = sig.Algorithm,
                    Error = "Public key fingerprint does not match keyId."
                };
            }

            // Rebuild the PAE from the envelope
            var payloadBytes = Convert.FromBase64String(base64Payload);
            var paeBytes = DssePae.Encode(payloadType, payloadBytes);

            // Create verifier and verify
            using var verifier = VerifierFactory.CreateFromPublicKey(spkiBytes, sig.Algorithm);
            var signatureBytes = Convert.FromBase64String(sig.Sig);
            var isValid = verifier.Verify(paeBytes, signatureBytes);

            TimestampVerificationInfo? timestampInfo = null;
            if (isValid && sig.TimestampToken is not null)
            {
                timestampInfo = TimestampValidator.Validate(sig.TimestampToken, signatureBytes);
            }

            return new AttestationSignatureResult
            {
                KeyId = sig.KeyId,
                IsValid = isValid,
                Algorithm = sig.Algorithm,
                Error = isValid ? null : "Signature verification failed.",
                TimestampInfo = timestampInfo
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new AttestationSignatureResult
            {
                KeyId = sig.KeyId,
                IsValid = false,
                Algorithm = sig.Algorithm,
                Error = ex.Message
            };
        }
    }
}
