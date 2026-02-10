using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Sbom;

namespace Sigil.Signing;

/// <summary>
/// Creates and appends signatures to manifest envelopes covering multiple files.
/// </summary>
public static class ManifestSigner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Builds subject descriptors for all files relative to a base path.
    /// Files are sorted by relative path for deterministic ordering.
    /// </summary>
    public static List<SubjectDescriptor> BuildSubjects(string basePath, IReadOnlyList<string> filePaths)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);
        ArgumentNullException.ThrowIfNull(filePaths);

        if (filePaths.Count == 0)
            throw new ArgumentException("At least one file is required.", nameof(filePaths));

        var fullBase = Path.GetFullPath(basePath);
        var subjects = new List<SubjectDescriptor>(filePaths.Count);

        // Build subjects sorted by relative path for deterministic ordering
        var sorted = filePaths
            .Select(f => Path.GetFullPath(f))
            .OrderBy(f => Path.GetRelativePath(fullBase, f).Replace('\\', '/'), StringComparer.Ordinal)
            .ToList();

        foreach (var fullPath in sorted)
        {
            // Path traversal protection: ensure file is within base directory
            if (!fullPath.StartsWith(fullBase, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(
                    $"File path '{fullPath}' is outside the base directory '{fullBase}'.", nameof(filePaths));

            var relativePath = Path.GetRelativePath(fullBase, fullPath).Replace('\\', '/');
            var fileBytes = File.ReadAllBytes(fullPath);
            var (sha256, sha512) = HashAlgorithms.ComputeDigests(fileBytes);

            var sbom = SbomDetector.TryDetect(fileBytes);

            subjects.Add(new SubjectDescriptor
            {
                Name = relativePath,
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                },
                MediaType = sbom?.MediaType,
                Metadata = sbom?.ToDictionary()
            });
        }

        return subjects;
    }

    /// <summary>
    /// Signs multiple files and produces a manifest envelope.
    /// </summary>
    public static ManifestEnvelope Sign(
        string basePath,
        IReadOnlyList<string> filePaths,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null)
    {
        var subjects = BuildSubjects(basePath, filePaths);

        var envelope = new ManifestEnvelope
        {
            Subjects = subjects
        };

        AppendSignature(envelope, signer, fingerprint, label);
        return envelope;
    }

    /// <summary>
    /// Asynchronously signs multiple files and produces a manifest envelope.
    /// Required for vault-backed signers where Sign() is not supported.
    /// </summary>
    public static async Task<ManifestEnvelope> SignAsync(
        string basePath,
        IReadOnlyList<string> filePaths,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null,
        CancellationToken ct = default)
    {
        var subjects = BuildSubjects(basePath, filePaths);

        var envelope = new ManifestEnvelope
        {
            Subjects = subjects
        };

        await AppendSignatureAsync(envelope, signer, fingerprint, label, ct).ConfigureAwait(false);
        return envelope;
    }

    /// <summary>
    /// Appends a new signature to an existing manifest envelope.
    /// </summary>
    public static void AppendSignature(
        ManifestEnvelope envelope,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(signer);

        var algorithm = signer.Algorithm.ToCanonicalName();
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        var payloadToSign = BuildManifestSigningPayload(
            envelope.Subjects, envelope.Version, fingerprint.Value, algorithm, timestamp, label);
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
    /// Asynchronously appends a new signature to an existing manifest envelope.
    /// </summary>
    public static async Task AppendSignatureAsync(
        ManifestEnvelope envelope,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(signer);

        var algorithm = signer.Algorithm.ToCanonicalName();
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        var payloadToSign = BuildManifestSigningPayload(
            envelope.Subjects, envelope.Version, fingerprint.Value, algorithm, timestamp, label);
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
    /// Serializes a manifest envelope to JSON.
    /// </summary>
    public static string Serialize(ManifestEnvelope envelope)
    {
        return JsonSerializer.Serialize(envelope, JsonOptions);
    }

    /// <summary>
    /// Deserializes a manifest envelope from JSON.
    /// </summary>
    public static ManifestEnvelope Deserialize(string json)
    {
        return JsonSerializer.Deserialize<ManifestEnvelope>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize manifest envelope.");
    }

    /// <summary>
    /// Builds the canonical payload that gets signed:
    /// JCS(subjects-array) + JCS(signed-attributes).
    /// No separate artifact hash — digests are embedded in each SubjectDescriptor.
    /// Adding, removing, or reordering files invalidates the signature.
    /// </summary>
    internal static byte[] BuildManifestSigningPayload(
        List<SubjectDescriptor> subjects,
        string version,
        string keyId,
        string algorithm,
        string timestamp,
        string? label)
    {
        var subjectsJson = JsonSerializer.Serialize(subjects);
        var canonicalizedSubjects = new JsonCanonicalizer(subjectsJson).GetEncodedUTF8();

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

        var payload = new byte[canonicalizedSubjects.Length + canonicalizedAttrs.Length];
        Buffer.BlockCopy(canonicalizedSubjects, 0, payload, 0, canonicalizedSubjects.Length);
        Buffer.BlockCopy(canonicalizedAttrs, 0, payload, canonicalizedSubjects.Length, canonicalizedAttrs.Length);
        return payload;
    }
}
