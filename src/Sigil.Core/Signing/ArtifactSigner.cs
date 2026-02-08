using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Sbom;

namespace Sigil.Signing;

/// <summary>
/// Creates and appends signatures to a detached signature envelope.
/// </summary>
public static class ArtifactSigner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Signs an artifact file and produces a signature envelope.
    /// </summary>
    public static SignatureEnvelope Sign(
        string artifactPath,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentNullException.ThrowIfNull(signer);

        if (!File.Exists(artifactPath))
            throw new FileNotFoundException("Artifact not found.", artifactPath);

        var fileBytes = File.ReadAllBytes(artifactPath);
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(fileBytes);

        var sbom = SbomDetector.TryDetect(fileBytes);

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = Path.GetFileName(artifactPath),
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                },
                MediaType = sbom?.MediaType,
                Metadata = sbom?.ToDictionary()
            }
        };

        AppendSignature(envelope, fileBytes, signer, fingerprint, label);
        return envelope;
    }

    /// <summary>
    /// Appends a new signature to an existing envelope.
    /// The signer's public key is embedded in the signature entry for self-contained verification.
    /// </summary>
    public static void AppendSignature(
        SignatureEnvelope envelope,
        byte[] artifactBytes,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(artifactBytes);
        ArgumentNullException.ThrowIfNull(signer);

        // Compute all metadata before signing so it's included in the payload
        var algorithm = signer.Algorithm.ToCanonicalName();
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        var payloadToSign = BuildSigningPayload(
            envelope.Subject, artifactBytes, envelope.Version,
            fingerprint.Value, algorithm, timestamp, label);
        var signatureBytes = signer.Sign(payloadToSign);

        var entry = new SignatureEntry
        {
            KeyId = fingerprint.Value,
            Algorithm = algorithm,
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Value = Convert.ToBase64String(signatureBytes),
            Timestamp = timestamp,
            Label = label
        };

        envelope.Signatures.Add(entry);
    }

    /// <summary>
    /// Asynchronously signs an artifact file and produces a signature envelope.
    /// Required for vault-backed signers where Sign() is not supported.
    /// </summary>
    public static async Task<SignatureEnvelope> SignAsync(
        string artifactPath,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentNullException.ThrowIfNull(signer);

        if (!File.Exists(artifactPath))
            throw new FileNotFoundException("Artifact not found.", artifactPath);

        var fileBytes = await File.ReadAllBytesAsync(artifactPath, ct).ConfigureAwait(false);
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(fileBytes);

        var sbom = SbomDetector.TryDetect(fileBytes);

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = Path.GetFileName(artifactPath),
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                },
                MediaType = sbom?.MediaType,
                Metadata = sbom?.ToDictionary()
            }
        };

        await AppendSignatureAsync(envelope, fileBytes, signer, fingerprint, label, ct).ConfigureAwait(false);
        return envelope;
    }

    /// <summary>
    /// Asynchronously appends a new signature to an existing envelope.
    /// Required for vault-backed signers where Sign() is not supported.
    /// </summary>
    public static async Task AppendSignatureAsync(
        SignatureEnvelope envelope,
        byte[] artifactBytes,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(artifactBytes);
        ArgumentNullException.ThrowIfNull(signer);

        var algorithm = signer.Algorithm.ToCanonicalName();
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        var payloadToSign = BuildSigningPayload(
            envelope.Subject, artifactBytes, envelope.Version,
            fingerprint.Value, algorithm, timestamp, label);
        var signatureBytes = await signer.SignAsync(payloadToSign, ct).ConfigureAwait(false);

        var entry = new SignatureEntry
        {
            KeyId = fingerprint.Value,
            Algorithm = algorithm,
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Value = Convert.ToBase64String(signatureBytes),
            Timestamp = timestamp,
            Label = label
        };

        envelope.Signatures.Add(entry);
    }

    /// <summary>
    /// Serializes a signature envelope to JSON.
    /// </summary>
    public static string Serialize(SignatureEnvelope envelope)
    {
        return JsonSerializer.Serialize(envelope, JsonOptions);
    }

    /// <summary>
    /// Deserializes a signature envelope from JSON.
    /// </summary>
    public static SignatureEnvelope Deserialize(string json)
    {
        return JsonSerializer.Deserialize<SignatureEnvelope>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize signature envelope.");
    }

    /// <summary>
    /// Builds the canonical payload that gets signed:
    /// JCS(subject) + SHA-256(artifact bytes) + JCS(signed attributes).
    /// This binds the signature to the subject metadata, artifact content,
    /// and all signature entry metadata (preventing timestamp/label tampering).
    /// </summary>
    internal static byte[] BuildSigningPayload(
        SubjectDescriptor subject,
        byte[] artifactBytes,
        string version,
        string keyId,
        string algorithm,
        string timestamp,
        string? label)
    {
        var subjectJson = JsonSerializer.Serialize(subject);
        var canonicalizedSubject = new JsonCanonicalizer(subjectJson).GetEncodedUTF8();
        var artifactDigest = HashAlgorithms.Sha256(artifactBytes);

        // Signed attributes: everything that should be tamper-proof
        var signedAttrs = new Dictionary<string, string>
        {
            ["algorithm"] = algorithm,
            ["keyId"] = keyId,
            ["timestamp"] = timestamp,
            ["version"] = version
        };
        if (label is not null)
            signedAttrs["label"] = label;

        var attrsJson = JsonSerializer.Serialize(signedAttrs);
        var canonicalizedAttrs = new JsonCanonicalizer(attrsJson).GetEncodedUTF8();

        var payload = new byte[canonicalizedSubject.Length + artifactDigest.Length + canonicalizedAttrs.Length];
        Buffer.BlockCopy(canonicalizedSubject, 0, payload, 0, canonicalizedSubject.Length);
        Buffer.BlockCopy(artifactDigest, 0, payload, canonicalizedSubject.Length, artifactDigest.Length);
        Buffer.BlockCopy(canonicalizedAttrs, 0, payload,
            canonicalizedSubject.Length + artifactDigest.Length, canonicalizedAttrs.Length);
        return payload;
    }
}
