using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Sigil.Timestamping;

namespace Sigil.Pe;

/// <summary>
/// Applies RFC 3161 timestamps to Authenticode PKCS#7 signatures.
/// The timestamp is added as an unauthenticated attribute (OID 1.3.6.1.4.1.311.3.3.1).
/// </summary>
public static class AuthenticodeTimestamper
{
    // Microsoft Authenticode timestamp counter-signature OID
    private const string Rfc3161CounterSignatureOid = "1.3.6.1.4.1.311.3.3.1";

    /// <summary>
    /// Applies an RFC 3161 timestamp to Authenticode PKCS#7 bytes.
    /// Returns updated PKCS#7 bytes with the timestamp as an unauthenticated attribute.
    /// </summary>
    public static async Task<AuthenticodeResult<byte[]>> ApplyTimestampAsync(
        byte[] pkcs7Bytes, Uri tsaUri, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(pkcs7Bytes);
        ArgumentNullException.ThrowIfNull(tsaUri);

        // Extract signature value from PKCS#7
        SignedCms signedCms;
        try
        {
            signedCms = new SignedCms();
            signedCms.Decode(pkcs7Bytes);
        }
        catch (CryptographicException ex)
        {
            return AuthenticodeResult<byte[]>.Fail(
                AuthenticodeErrorKind.TimestampFailed,
                $"Failed to decode PKCS#7 for timestamping: {ex.Message}");
        }

        if (signedCms.SignerInfos.Count == 0)
            return AuthenticodeResult<byte[]>.Fail(
                AuthenticodeErrorKind.TimestampFailed,
                "PKCS#7 contains no signer information.");

        // Get the signature value to timestamp
        byte[] signatureValue = signedCms.SignerInfos[0].GetSignature();

        // Request timestamp from TSA
        using var tsaClient = new TsaClient();
        var tsaResult = await tsaClient.RequestTimestampAsync(tsaUri, signatureValue, ct)
            .ConfigureAwait(false);

        if (!tsaResult.IsSuccess)
            return AuthenticodeResult<byte[]>.Fail(
                AuthenticodeErrorKind.TimestampFailed,
                $"TSA request failed: {tsaResult.ErrorMessage}");

        byte[] timestampToken = tsaResult.Value;

        // Add timestamp as unauthenticated attribute
        try
        {
            var tsAttribute = new AsnEncodedData(
                new Oid(Rfc3161CounterSignatureOid),
                timestampToken);

            signedCms.SignerInfos[0].AddUnsignedAttribute(tsAttribute);
            return AuthenticodeResult<byte[]>.Ok(signedCms.Encode());
        }
        catch (CryptographicException ex)
        {
            return AuthenticodeResult<byte[]>.Fail(
                AuthenticodeErrorKind.TimestampFailed,
                $"Failed to add timestamp attribute: {ex.Message}");
        }
    }
}
