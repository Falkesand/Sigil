using Sigil.Signing;

namespace Sigil.Timestamping;

/// <summary>
/// Applies an RFC 3161 timestamp token to a signature entry.
/// </summary>
public static class TimestampApplier
{
    public static async Task<TimestampResult<SignatureEntry>> ApplyAsync(
        SignatureEntry entry, Uri tsaUri,
        TsaClient? tsaClient = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(tsaUri);

        var ownedClient = tsaClient is null ? new TsaClient() : null;
        var client = tsaClient ?? ownedClient!;
        try
        {
            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(entry.Value);
            }
            catch (FormatException)
            {
                return TimestampResult<SignatureEntry>.Fail(
                    TimestampErrorKind.InvalidToken, "Signature value is not valid base64.");
            }

            var result = await client.RequestTimestampAsync(tsaUri, signatureBytes, ct).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                return TimestampResult<SignatureEntry>.Fail(result.ErrorKind, result.ErrorMessage);
            }

            var timestampedEntry = new SignatureEntry
            {
                KeyId = entry.KeyId,
                Algorithm = entry.Algorithm,
                PublicKey = entry.PublicKey,
                Value = entry.Value,
                Timestamp = entry.Timestamp,
                Label = entry.Label,
                TimestampToken = Convert.ToBase64String(result.Value),
                OidcToken = entry.OidcToken,
                OidcIssuer = entry.OidcIssuer,
                OidcIdentity = entry.OidcIdentity
            };

            return TimestampResult<SignatureEntry>.Ok(timestampedEntry);
        }
        finally
        {
            ownedClient?.Dispose();
        }
    }
}
