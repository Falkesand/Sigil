namespace Sigil.Crypto;

public interface ISigner : IDisposable
{
    SigningAlgorithm Algorithm { get; }
    byte[] PublicKey { get; }
    byte[] Sign(byte[] data);
}

public interface IVerifier
{
    SigningAlgorithm Algorithm { get; }
    byte[] PublicKey { get; }
    bool Verify(byte[] data, byte[] signature);
}
