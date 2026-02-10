using Sigil.Signing;

namespace Sigil.Transparency.Remote;

public static class LogSubmitter
{
    public static async Task<RemoteLogResult<SignatureEntry>> SubmitAsync(
        SignatureEntry entry, SubjectDescriptor subject,
        IRemoteLog remoteLog, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(remoteLog);

        var result = await remoteLog.AppendAsync(entry, subject, ct).ConfigureAwait(false);

        if (!result.IsSuccess)
        {
            return RemoteLogResult<SignatureEntry>.Fail(result.ErrorKind, result.ErrorMessage);
        }

        var receipt = result.Value;

        var loggedEntry = new SignatureEntry
        {
            KeyId = entry.KeyId,
            Algorithm = entry.Algorithm,
            PublicKey = entry.PublicKey,
            Value = entry.Value,
            Timestamp = entry.Timestamp,
            Label = entry.Label,
            TimestampToken = entry.TimestampToken,
            OidcToken = entry.OidcToken,
            OidcIssuer = entry.OidcIssuer,
            OidcIdentity = entry.OidcIdentity,
            TransparencyLogUrl = receipt.LogUrl,
            TransparencyLogIndex = receipt.LogIndex,
            TransparencySignedCheckpoint = receipt.SignedCheckpoint,
            TransparencyInclusionProof = receipt.InclusionProof
        };

        return RemoteLogResult<SignatureEntry>.Ok(loggedEntry);
    }
}
