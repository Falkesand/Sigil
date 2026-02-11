using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Sbom;

namespace Sigil.Signing;

/// <summary>
/// Signs archive files (ZIP, tar.gz, tar) producing a manifest envelope with per-entry digests.
/// Reuses <see cref="ManifestSigner.BuildManifestSigningPayload"/> for the signing payload.
/// </summary>
public static class ArchiveSigner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Builds subject descriptors for all entries in an archive.
    /// Entries are sorted by path for deterministic ordering.
    /// For .nupkg archives, NuGet metadata from the .nuspec is attached to each subject.
    /// </summary>
    public static List<SubjectDescriptor> BuildSubjects(string archivePath, ArchiveFormat format)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        // Extract NuGet metadata if this is a .nupkg archive
        Dictionary<string, string>? nugetMetadata = null;
        if (format == ArchiveFormat.Zip
            && archivePath.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
        {
            nugetMetadata = NuspecExtractor.TryExtract(archivePath);
        }

        var subjects = new List<SubjectDescriptor>();

        foreach (var (entry, content) in ArchiveEntryReader.ReadEntries(archivePath, format))
        {
            using var contentStream = content;
            var bytes = ToByteArray(contentStream);

            var (sha256, sha512) = HashAlgorithms.ComputeDigests(bytes);

            var sbom = SbomDetector.TryDetect(bytes);

            // Merge metadata from SBOM detection and NuGet metadata
            Dictionary<string, string>? metadata = null;
            if (sbom is not null)
                metadata = sbom.ToDictionary();
            if (nugetMetadata is not null)
            {
                metadata ??= new Dictionary<string, string>();
                foreach (var (key, value) in nugetMetadata)
                    metadata.TryAdd(key, value);
            }

            subjects.Add(new SubjectDescriptor
            {
                Name = entry.RelativePath,
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = sha256,
                    ["sha512"] = sha512
                },
                MediaType = sbom?.MediaType,
                Metadata = metadata
            });
        }

        if (subjects.Count == 0)
            throw new ArgumentException("Archive contains no file entries.", nameof(archivePath));

        // Sort by path for deterministic ordering
        subjects.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

        return subjects;
    }

    /// <summary>
    /// Signs an archive and produces a manifest envelope with Kind="archive".
    /// </summary>
    public static ManifestEnvelope Sign(
        string archivePath,
        ArchiveFormat format,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null)
    {
        var subjects = BuildSubjects(archivePath, format);

        var envelope = new ManifestEnvelope
        {
            Kind = "archive",
            Subjects = subjects
        };

        AppendSignature(envelope, signer, fingerprint, label);
        return envelope;
    }

    /// <summary>
    /// Asynchronously signs an archive. Required for vault-backed signers.
    /// </summary>
    public static async Task<ManifestEnvelope> SignAsync(
        string archivePath,
        ArchiveFormat format,
        ISigner signer,
        KeyFingerprint fingerprint,
        string? label = null,
        CancellationToken ct = default)
    {
        var subjects = BuildSubjects(archivePath, format);

        var envelope = new ManifestEnvelope
        {
            Kind = "archive",
            Subjects = subjects
        };

        await AppendSignatureAsync(envelope, signer, fingerprint, label, ct).ConfigureAwait(false);
        return envelope;
    }

    /// <summary>
    /// Appends a new signature to an existing archive envelope.
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

        var payloadToSign = ManifestSigner.BuildManifestSigningPayload(
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
    /// Asynchronously appends a new signature to an existing archive envelope.
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

        var payloadToSign = ManifestSigner.BuildManifestSigningPayload(
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
    /// Serializes an archive envelope to JSON.
    /// </summary>
    public static string Serialize(ManifestEnvelope envelope)
    {
        return JsonSerializer.Serialize(envelope, JsonOptions);
    }

    /// <summary>
    /// Deserializes an archive envelope from JSON.
    /// </summary>
    public static ManifestEnvelope Deserialize(string json)
    {
        return JsonSerializer.Deserialize<ManifestEnvelope>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize archive envelope.");
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
