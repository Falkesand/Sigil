namespace Sigil.Crypto;

public interface ISigner : IDisposable
{
    SigningAlgorithm Algorithm { get; }
    byte[] PublicKey { get; }
    byte[] Sign(byte[] data);
    string ExportPublicKeyPem();
    byte[] ExportPrivateKeyPemBytes();
    byte[] ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char> password);
}

public interface IVerifier : IDisposable
{
    SigningAlgorithm Algorithm { get; }
    byte[] PublicKey { get; }
    bool Verify(byte[] data, byte[] signature);
}
