using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Timestamping;

namespace Sigil.Signing;

/// <summary>
/// Verifies manifest envelopes: per-file digest checks and shared signature verification.
/// </summary>
public static class ManifestValidator
{
    /// <summary>
    /// Verifies all files and signatures in a manifest envelope.
    /// </summary>
    public static ManifestVerificationResult Verify(string basePath, ManifestEnvelope envelope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);
        ArgumentNullException.ThrowIfNull(envelope);

        if (envelope.Subjects.Count == 0)
        {
            return new ManifestVerificationResult
            {
                FileResults = [new FileVerificationResult
                {
                    Name = "(empty)",
                    DigestMatch = false,
                    Error = "Manifest contains no subjects."
                }],
                Signatures = []
            };
        }

        var fullBase = Path.GetFullPath(basePath);

        // Step 1: Verify each file's digests
        var fileResults = new List<FileVerificationResult>(envelope.Subjects.Count);

        foreach (var subject in envelope.Subjects)
        {
            fileResults.Add(VerifyFile(fullBase, subject));
        }

        // Step 2: Verify each signature
        var sigResults = new List<SignatureVerificationResult>(envelope.Signatures.Count);

        foreach (var sig in envelope.Signatures)
        {
            sigResults.Add(VerifySingleSignature(sig, envelope.Subjects, envelope.Version));
        }

        return new ManifestVerificationResult
        {
            FileResults = fileResults,
            Signatures = sigResults
        };
    }

    private static FileVerificationResult VerifyFile(string fullBase, SubjectDescriptor subject)
    {
        try
        {
            // Path traversal protection
            var resolvedPath = Path.GetFullPath(Path.Combine(fullBase, subject.Name));
            if (!resolvedPath.StartsWith(fullBase, StringComparison.OrdinalIgnoreCase))
            {
                return new FileVerificationResult
                {
                    Name = subject.Name,
                    DigestMatch = false,
                    Error = "Path traversal detected: subject resolves outside base directory."
                };
            }

            if (!File.Exists(resolvedPath))
            {
                return new FileVerificationResult
                {
                    Name = subject.Name,
                    DigestMatch = false,
                    Error = "File not found."
                };
            }

            var fileBytes = File.ReadAllBytes(resolvedPath);
            var (sha256, sha512) = HashAlgorithms.ComputeDigests(fileBytes);

            bool digestMatch = true;
            if (subject.Digests.TryGetValue("sha256", out var expectedSha256))
                digestMatch &= string.Equals(sha256, expectedSha256, StringComparison.OrdinalIgnoreCase);
            if (subject.Digests.TryGetValue("sha512", out var expectedSha512))
                digestMatch &= string.Equals(sha512, expectedSha512, StringComparison.OrdinalIgnoreCase);

            return new FileVerificationResult
            {
                Name = subject.Name,
                DigestMatch = digestMatch,
                Error = digestMatch ? null : "Digest mismatch."
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new FileVerificationResult
            {
                Name = subject.Name,
                DigestMatch = false,
                Error = ex.Message
            };
        }
    }

    private static SignatureVerificationResult VerifySingleSignature(
        SignatureEntry sig,
        List<SubjectDescriptor> subjects,
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
                    Algorithm = sig.Algorithm,
                    Label = sig.Label,
                    Error = "Public key not found in signature entry."
                };
            }

            var spkiBytes = Convert.FromBase64String(sig.PublicKey);

            var computedFingerprint = KeyFingerprint.Compute(spkiBytes);
            if (computedFingerprint.Value != sig.KeyId)
            {
                return new SignatureVerificationResult
                {
                    KeyId = sig.KeyId,
                    IsValid = false,
                    Algorithm = sig.Algorithm,
                    Label = sig.Label,
                    Error = "Public key fingerprint does not match keyId."
                };
            }

            var signingPayload = ManifestSigner.BuildManifestSigningPayload(
                subjects, version, sig.KeyId, sig.Algorithm, sig.Timestamp, sig.Label);

            using var verifier = VerifierFactory.CreateFromPublicKey(spkiBytes, sig.Algorithm);
            var signatureBytes = Convert.FromBase64String(sig.Value);
            var isValid = verifier.Verify(signingPayload, signatureBytes);

            TimestampVerificationInfo? timestampInfo = null;
            if (isValid && sig.TimestampToken is not null)
            {
                timestampInfo = TimestampValidator.Validate(sig.TimestampToken, signatureBytes);
            }

            return new SignatureVerificationResult
            {
                KeyId = sig.KeyId,
                IsValid = isValid,
                Algorithm = sig.Algorithm,
                Label = sig.Label,
                Error = isValid ? null : "Signature verification failed.",
                TimestampInfo = timestampInfo
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new SignatureVerificationResult
            {
                KeyId = sig.KeyId,
                IsValid = false,
                Algorithm = sig.Algorithm,
                Label = sig.Label,
                Error = ex.Message
            };
        }
    }
}
