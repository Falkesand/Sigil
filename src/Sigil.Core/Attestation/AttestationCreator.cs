using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Attestation;

/// <summary>
/// Creates and signs DSSE-wrapped in-toto attestations.
/// </summary>
public static class AttestationCreator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Creates an in-toto statement for an artifact with the given predicate.
    /// </summary>
    public static InTotoStatement CreateStatement(
        string artifactPath,
        string predicateType,
        JsonElement? predicate = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(predicateType);

        if (!File.Exists(artifactPath))
            throw new FileNotFoundException("Artifact not found.", artifactPath);

        var fileBytes = File.ReadAllBytes(artifactPath);
        return CreateStatement(Path.GetFileName(artifactPath), fileBytes, predicateType, predicate);
    }

    /// <summary>
    /// Creates an in-toto statement from artifact bytes.
    /// </summary>
    public static InTotoStatement CreateStatement(
        string artifactName,
        byte[] artifactBytes,
        string predicateType,
        JsonElement? predicate = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactName);
        ArgumentNullException.ThrowIfNull(artifactBytes);
        ArgumentException.ThrowIfNullOrWhiteSpace(predicateType);

        var sha256 = HashAlgorithms.Sha256Hex(artifactBytes);

        return new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = artifactName,
                    Digest = new Dictionary<string, string> { ["sha256"] = sha256 }
                }
            ],
            PredicateType = predicateType,
            Predicate = predicate
        };
    }

    /// <summary>
    /// Signs a statement and wraps it in a DSSE envelope.
    /// </summary>
    public static DsseEnvelope Sign(
        InTotoStatement statement,
        ISigner signer,
        KeyFingerprint fingerprint)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(signer);

        var statementJson = JsonSerializer.SerializeToUtf8Bytes(statement, JsonOptions);
        var payload = Convert.ToBase64String(statementJson);

        var envelope = new DsseEnvelope { Payload = payload };

        AppendSignature(envelope, signer, fingerprint);
        return envelope;
    }

    /// <summary>
    /// Asynchronously signs a statement and wraps it in a DSSE envelope.
    /// Required for vault-backed signers.
    /// </summary>
    public static async Task<DsseEnvelope> SignAsync(
        InTotoStatement statement,
        ISigner signer,
        KeyFingerprint fingerprint,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(signer);

        var statementJson = JsonSerializer.SerializeToUtf8Bytes(statement, JsonOptions);
        var payload = Convert.ToBase64String(statementJson);

        var envelope = new DsseEnvelope { Payload = payload };

        await AppendSignatureAsync(envelope, signer, fingerprint, ct).ConfigureAwait(false);
        return envelope;
    }

    /// <summary>
    /// Appends a new signature to an existing DSSE envelope.
    /// </summary>
    public static void AppendSignature(
        DsseEnvelope envelope,
        ISigner signer,
        KeyFingerprint fingerprint)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(signer);

        var payloadBytes = Convert.FromBase64String(envelope.Payload);
        var paeBytes = DssePae.Encode(envelope.PayloadType, payloadBytes);

        var algorithm = signer.Algorithm.ToCanonicalName();
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        var signatureBytes = signer.Sign(paeBytes);

        var entry = new DsseSignature
        {
            KeyId = fingerprint.Value,
            Sig = Convert.ToBase64String(signatureBytes),
            Algorithm = algorithm,
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Timestamp = timestamp
        };

        envelope.Signatures.Add(entry);
    }

    /// <summary>
    /// Asynchronously appends a new signature to an existing DSSE envelope.
    /// Required for vault-backed signers.
    /// </summary>
    public static async Task AppendSignatureAsync(
        DsseEnvelope envelope,
        ISigner signer,
        KeyFingerprint fingerprint,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(signer);

        var payloadBytes = Convert.FromBase64String(envelope.Payload);
        var paeBytes = DssePae.Encode(envelope.PayloadType, payloadBytes);

        var algorithm = signer.Algorithm.ToCanonicalName();
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        var signatureBytes = await signer.SignAsync(paeBytes, ct).ConfigureAwait(false);

        var entry = new DsseSignature
        {
            KeyId = fingerprint.Value,
            Sig = Convert.ToBase64String(signatureBytes),
            Algorithm = algorithm,
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Timestamp = timestamp
        };

        envelope.Signatures.Add(entry);
    }

    /// <summary>
    /// Serializes a DSSE envelope to JSON.
    /// </summary>
    public static string Serialize(DsseEnvelope envelope)
    {
        return JsonSerializer.Serialize(envelope, JsonOptions);
    }

    /// <summary>
    /// Deserializes a DSSE envelope from JSON.
    /// </summary>
    public static AttestationResult<DsseEnvelope> Deserialize(string json)
    {
        try
        {
            var envelope = JsonSerializer.Deserialize<DsseEnvelope>(json, JsonOptions);
            if (envelope is null)
                return AttestationResult<DsseEnvelope>.Fail(
                    AttestationErrorKind.DeserializationFailed,
                    "Failed to deserialize DSSE envelope.");

            return AttestationResult<DsseEnvelope>.Ok(envelope);
        }
        catch (JsonException ex)
        {
            return AttestationResult<DsseEnvelope>.Fail(
                AttestationErrorKind.DeserializationFailed,
                $"Invalid DSSE envelope JSON: {ex.Message}");
        }
    }

    /// <summary>
    /// Extracts the in-toto statement from a DSSE envelope.
    /// </summary>
    public static AttestationResult<InTotoStatement> ExtractStatement(DsseEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        try
        {
            var payloadBytes = Convert.FromBase64String(envelope.Payload);
            var statement = JsonSerializer.Deserialize<InTotoStatement>(payloadBytes, JsonOptions);

            if (statement is null)
                return AttestationResult<InTotoStatement>.Fail(
                    AttestationErrorKind.DeserializationFailed,
                    "Failed to deserialize in-toto statement from payload.");

            return AttestationResult<InTotoStatement>.Ok(statement);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return AttestationResult<InTotoStatement>.Fail(
                AttestationErrorKind.DeserializationFailed,
                $"Invalid statement payload: {ex.Message}");
        }
    }
}
