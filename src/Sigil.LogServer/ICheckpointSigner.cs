namespace Sigil.LogServer;

public interface ICheckpointSigner : IDisposable
{
    byte[] PublicKeySpki { get; }
    string PublicKeyBase64 { get; }
    string SignCheckpoint(long treeSize, string rootHash, string timestamp);
}
