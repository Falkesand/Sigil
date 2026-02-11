using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Timestamping;

namespace Sigil.Signing;

/// <summary>
/// Verifies archive envelopes: per-entry digest checks and shared signature verification.
/// </summary>
public static class ArchiveValidator
{
    /// <summary>
    /// Verifies all entries and signatures in an archive envelope against an archive file.
    /// </summary>
    public static ArchiveValidationResult Verify(string archivePath, ManifestEnvelope envelope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        ArgumentNullException.ThrowIfNull(envelope);

        if (envelope.Subjects.Count == 0)
        {
            return new ArchiveValidationResult
            {
                Entries = [new ArchiveEntryValidation
                {
                    Name = "(empty)",
                    DigestMatch = false,
                    Error = "Envelope contains no subjects."
                }],
                Signatures = [],
                ExtraEntries = []
            };
        }

        var format = ArchiveDetector.Detect(archivePath)
            ?? throw new InvalidOperationException($"Unrecognized archive format: '{archivePath}'.");

        // Build a map of actual archive entries and their digests
        var actualEntries = new Dictionary<string, (string sha256, string sha512)>(StringComparer.Ordinal);
        foreach (var (entry, content) in ArchiveEntryReader.ReadEntries(archivePath, format))
        {
            using var contentStream = content;
            var bytes = ToByteArray(contentStream);
            var (sha256, sha512) = HashAlgorithms.ComputeDigests(bytes);
            actualEntries[entry.RelativePath] = (sha256, sha512);
        }

        // Step 1: Verify each subject's digests
        var entryResults = new List<ArchiveEntryValidation>(envelope.Subjects.Count);
        var coveredPaths = new HashSet<string>(StringComparer.Ordinal);

        foreach (var subject in envelope.Subjects)
        {
            coveredPaths.Add(subject.Name);
            entryResults.Add(VerifyEntry(subject, actualEntries));
        }

        // Step 2: Find extra entries in archive not covered by envelope
        var extraEntries = actualEntries.Keys
            .Where(k => !coveredPaths.Contains(k))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();

        // Step 3: Verify each signature
        var sigResults = new List<SignatureVerificationResult>(envelope.Signatures.Count);
        foreach (var sig in envelope.Signatures)
        {
            sigResults.Add(VerifySingleSignature(sig, envelope.Subjects, envelope.Version));
        }

        return new ArchiveValidationResult
        {
            Entries = entryResults,
            Signatures = sigResults,
            ExtraEntries = extraEntries
        };
    }

    /// <summary>
    /// Adapts an <see cref="ArchiveValidationResult"/> to a <see cref="VerificationResult"/>
    /// so the existing trust evaluator can evaluate archive signatures.
    /// </summary>
    public static VerificationResult ToVerificationResult(ArchiveValidationResult archive)
    {
        ArgumentNullException.ThrowIfNull(archive);

        return new VerificationResult
        {
            ArtifactDigestMatch = archive.AllDigestsMatch,
            Signatures = archive.Signatures.ToList()
        };
    }

    private static ArchiveEntryValidation VerifyEntry(
        SubjectDescriptor subject,
        Dictionary<string, (string sha256, string sha512)> actualEntries)
    {
        try
        {
            if (!actualEntries.TryGetValue(subject.Name, out var actual))
            {
                return new ArchiveEntryValidation
                {
                    Name = subject.Name,
                    DigestMatch = false,
                    Error = "Entry not found in archive."
                };
            }

            bool digestMatch = true;
            if (subject.Digests.TryGetValue("sha256", out var expectedSha256))
                digestMatch &= string.Equals(actual.sha256, expectedSha256, StringComparison.OrdinalIgnoreCase);
            if (subject.Digests.TryGetValue("sha512", out var expectedSha512))
                digestMatch &= string.Equals(actual.sha512, expectedSha512, StringComparison.OrdinalIgnoreCase);

            return new ArchiveEntryValidation
            {
                Name = subject.Name,
                DigestMatch = digestMatch,
                Error = digestMatch ? null : "Digest mismatch."
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new ArchiveEntryValidation
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

    private static byte[] ToByteArray(Stream stream)
    {
        if (stream is MemoryStream ms)
            return ms.ToArray();

        using var temp = new MemoryStream();
        stream.CopyTo(temp);
        return temp.ToArray();
    }
}
