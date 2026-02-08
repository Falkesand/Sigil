using System.Text.Json;
using System.Text.Json.Nodes;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Trust;

/// <summary>
/// Signs and verifies trust bundles. The signature covers the JCS-canonicalized
/// bundle with the signature field removed.
/// </summary>
public static class BundleSigner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static TrustResult<string> Serialize(TrustBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);

        try
        {
            var json = JsonSerializer.Serialize(bundle, JsonOptions);
            return TrustResult<string>.Ok(json);
        }
        catch (JsonException ex)
        {
            return TrustResult<string>.Fail(TrustErrorKind.SerializationFailed, ex.Message);
        }
    }

    public static TrustResult<TrustBundle> Deserialize(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        try
        {
            var bundle = JsonSerializer.Deserialize<TrustBundle>(json, JsonOptions);
            if (bundle is null)
                return TrustResult<TrustBundle>.Fail(TrustErrorKind.DeserializationFailed, "Deserialization returned null.");

            return TrustResult<TrustBundle>.Ok(bundle);
        }
        catch (JsonException ex)
        {
            return TrustResult<TrustBundle>.Fail(TrustErrorKind.DeserializationFailed, ex.Message);
        }
    }

    /// <summary>
    /// Signs a trust bundle and returns a new bundle with the signature field populated.
    /// </summary>
    public static TrustResult<TrustBundle> Sign(TrustBundle bundle, ISigner signer)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(signer);

        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        // Clear any existing signature before computing the signing payload
        bundle.Signature = null;

        var payloadBytes = BuildSigningPayload(bundle);
        var signatureBytes = signer.Sign(payloadBytes);

        bundle.Signature = new BundleSignature
        {
            KeyId = fingerprint.Value,
            Algorithm = signer.Algorithm.ToCanonicalName(),
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Value = Convert.ToBase64String(signatureBytes),
            Timestamp = timestamp
        };

        return TrustResult<TrustBundle>.Ok(bundle);
    }

    /// <summary>
    /// Asynchronously signs a trust bundle. Required for vault-backed signers.
    /// </summary>
    public static async Task<TrustResult<TrustBundle>> SignAsync(
        TrustBundle bundle, ISigner signer, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(signer);

        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
            System.Globalization.CultureInfo.InvariantCulture);

        bundle.Signature = null;

        var payloadBytes = BuildSigningPayload(bundle);
        var signatureBytes = await signer.SignAsync(payloadBytes, ct).ConfigureAwait(false);

        bundle.Signature = new BundleSignature
        {
            KeyId = fingerprint.Value,
            Algorithm = signer.Algorithm.ToCanonicalName(),
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Value = Convert.ToBase64String(signatureBytes),
            Timestamp = timestamp
        };

        return TrustResult<TrustBundle>.Ok(bundle);
    }

    /// <summary>
    /// Verifies a signed trust bundle against the expected authority fingerprint.
    /// Returns Ok(true) if valid, Ok(false) if signature doesn't verify,
    /// or Fail with error details.
    /// </summary>
    public static TrustResult<bool> Verify(string json, string authorityFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentException.ThrowIfNullOrWhiteSpace(authorityFingerprint);

        var deserializeResult = Deserialize(json);
        if (!deserializeResult.IsSuccess)
            return TrustResult<bool>.Fail(deserializeResult.ErrorKind, deserializeResult.ErrorMessage);

        var bundle = deserializeResult.Value;

        if (bundle.Signature is null)
            return TrustResult<bool>.Fail(TrustErrorKind.BundleInvalid, "Bundle is not signed.");

        // Verify authority fingerprint matches
        if (!string.Equals(bundle.Signature.KeyId, authorityFingerprint, StringComparison.Ordinal))
            return TrustResult<bool>.Fail(TrustErrorKind.AuthorityMismatch,
                $"Bundle signed by {bundle.Signature.KeyId}, expected {authorityFingerprint}.");

        // Verify the embedded public key fingerprint matches keyId
        byte[] spkiBytes;
        try
        {
            spkiBytes = Convert.FromBase64String(bundle.Signature.PublicKey);
        }
        catch (FormatException ex)
        {
            return TrustResult<bool>.Fail(TrustErrorKind.BundleInvalid,
                $"Invalid base64 in signature publicKey: {ex.Message}");
        }

        var computedFingerprint = KeyFingerprint.Compute(spkiBytes);
        if (computedFingerprint.Value != bundle.Signature.KeyId)
            return TrustResult<bool>.Fail(TrustErrorKind.BundleInvalid,
                "Signature publicKey fingerprint does not match keyId.");

        // Rebuild the signing payload (bundle without signature)
        var bodyWithoutSignature = RemoveSignatureField(json);
        var payloadBytes = CanonicalizeJson(bodyWithoutSignature);

        // Verify the cryptographic signature
        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(bundle.Signature.Value);
        }
        catch (FormatException ex)
        {
            return TrustResult<bool>.Fail(TrustErrorKind.BundleInvalid,
                $"Invalid base64 in signature value: {ex.Message}");
        }

        using var verifier = VerifierFactory.CreateFromPublicKey(spkiBytes, bundle.Signature.Algorithm);
        var isValid = verifier.Verify(payloadBytes, signatureBytes);

        return TrustResult<bool>.Ok(isValid);
    }

    /// <summary>
    /// Builds the canonical payload for signing: JCS of the bundle without the signature field.
    /// </summary>
    private static byte[] BuildSigningPayload(TrustBundle bundle)
    {
        // Serialize without signature (it should already be null)
        var json = JsonSerializer.Serialize(bundle, JsonOptions);
        return CanonicalizeJson(json);
    }

    /// <summary>
    /// JCS-canonicalizes a JSON string.
    /// </summary>
    private static byte[] CanonicalizeJson(string json)
    {
        return new JsonCanonicalizer(json).GetEncodedUTF8();
    }

    /// <summary>
    /// Removes the "signature" field from a JSON string using DOM manipulation,
    /// preserving the exact structure for verification.
    /// </summary>
    private static string RemoveSignatureField(string json)
    {
        var node = JsonNode.Parse(json);
        if (node is JsonObject obj)
        {
            obj.Remove("signature");
        }
        return node!.ToJsonString(JsonOptions);
    }
}
