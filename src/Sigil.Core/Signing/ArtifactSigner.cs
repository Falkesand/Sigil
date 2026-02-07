using System.Text;
using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Crypto;
using Sigil.Keys;

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

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = Path.GetFileName(artifactPath),
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                }
            }
        };

        AppendSignature(envelope, fileBytes, signer, fingerprint, label);
        return envelope;
    }

    /// <summary>
    /// Appends a new signature to an existing envelope.
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

        // Build the canonical payload to sign: subject descriptor (JCS-canonicalized) + artifact digest
        var payloadToSign = BuildSigningPayload(envelope.Subject, artifactBytes);
        var signatureBytes = signer.Sign(payloadToSign);

        var entry = new SignatureEntry
        {
            KeyId = fingerprint.Value,
            Algorithm = signer.Algorithm.ToCanonicalName(),
            Value = Convert.ToBase64String(signatureBytes),
            Timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture),
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
    /// JCS(subject) concatenated with the raw artifact bytes' SHA-256 digest.
    /// This binds the signature to both the subject metadata and the artifact content.
    /// </summary>
    internal static byte[] BuildSigningPayload(SubjectDescriptor subject, byte[] artifactBytes)
    {
        var subjectJson = JsonSerializer.Serialize(subject);
        var canonicalized = new JsonCanonicalizer(subjectJson).GetEncodedUTF8();
        var artifactDigest = HashAlgorithms.Sha256(artifactBytes);

        var payload = new byte[canonicalized.Length + artifactDigest.Length];
        Buffer.BlockCopy(canonicalized, 0, payload, 0, canonicalized.Length);
        Buffer.BlockCopy(artifactDigest, 0, payload, canonicalized.Length, artifactDigest.Length);
        return payload;
    }
}
