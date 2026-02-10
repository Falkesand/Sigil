using Sigil.Signing;

namespace Sigil.Transparency.Remote;

public interface IRemoteLog : IDisposable
{
    string LogUrl { get; }

    Task<RemoteLogResult<TransparencyReceipt>> AppendAsync(
        SignatureEntry entry, SubjectDescriptor subject, CancellationToken ct = default);

    Task<RemoteLogResult<SignedCheckpoint>> GetCheckpointAsync(CancellationToken ct = default);

    Task<RemoteLogResult<RemoteInclusionProof>> GetInclusionProofAsync(
        long leafIndex, CancellationToken ct = default);

    Task<RemoteLogResult<string>> GetPublicKeyAsync(CancellationToken ct = default);
}
