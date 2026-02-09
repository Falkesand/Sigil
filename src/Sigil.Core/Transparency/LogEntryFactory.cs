using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Crypto;
using Sigil.Signing;

namespace Sigil.Transparency;

public static class LogEntryFactory
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static TransparencyResult<LogEntry> Create(SignatureEnvelope envelope, int signatureIndex, long entryIndex)
    {
        if (signatureIndex < 0 || signatureIndex >= envelope.Signatures.Count)
            return TransparencyResult<LogEntry>.Fail(
                TransparencyErrorKind.InvalidEnvelope,
                $"Signature index {signatureIndex} is out of range. Envelope has {envelope.Signatures.Count} signature(s).");

        var signature = envelope.Signatures[signatureIndex];

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signature.Value);
        }
        catch (FormatException)
        {
            return TransparencyResult<LogEntry>.Fail(
                TransparencyErrorKind.InvalidEnvelope,
                "Signature value is not valid base64.");
        }

        var signatureDigest = "sha256:" + HashAlgorithms.Sha256Hex(signatureBytes);

        var artifactDigest = envelope.Subject.Digests.TryGetValue("sha256", out var sha256)
            ? "sha256:" + sha256
            : envelope.Subject.Digests.First().Key + ":" + envelope.Subject.Digests.First().Value;

        var timestamp = DateTime.UtcNow.ToString("o");

        // Build entry without leafHash to compute JCS hash
        var entryForHashing = new LogEntry
        {
            Index = entryIndex,
            Timestamp = timestamp,
            KeyId = signature.KeyId,
            Algorithm = signature.Algorithm,
            ArtifactName = envelope.Subject.Name,
            ArtifactDigest = artifactDigest,
            SignatureDigest = signatureDigest,
            Label = signature.Label,
            LeafHash = "" // placeholder, excluded from JCS via separate serialization
        };

        var leafHash = ComputeEntryLeafHash(entryForHashing);

        var entry = new LogEntry
        {
            Index = entryIndex,
            Timestamp = timestamp,
            KeyId = signature.KeyId,
            Algorithm = signature.Algorithm,
            ArtifactName = envelope.Subject.Name,
            ArtifactDigest = artifactDigest,
            SignatureDigest = signatureDigest,
            Label = signature.Label,
            LeafHash = leafHash
        };

        return TransparencyResult<LogEntry>.Ok(entry);
    }

    internal static string ComputeEntryLeafHash(LogEntry entry)
    {
        // Serialize without leafHash for deterministic hashing
        var hashInput = new Dictionary<string, object?>
        {
            ["index"] = entry.Index,
            ["timestamp"] = entry.Timestamp,
            ["keyId"] = entry.KeyId,
            ["algorithm"] = entry.Algorithm,
            ["artifactName"] = entry.ArtifactName,
            ["artifactDigest"] = entry.ArtifactDigest,
            ["signatureDigest"] = entry.SignatureDigest
        };

        if (entry.Label is not null)
            hashInput["label"] = entry.Label;

        var json = JsonSerializer.Serialize(hashInput, SerializerOptions);
        var canonical = new JsonCanonicalizer(json).GetEncodedUTF8();
        var leafHashBytes = MerkleTree.ComputeLeafHash(canonical);
        return Convert.ToHexStringLower(leafHashBytes);
    }
}
