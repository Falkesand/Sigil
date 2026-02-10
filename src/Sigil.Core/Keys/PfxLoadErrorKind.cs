namespace Sigil.Keys;

public enum PfxLoadErrorKind
{
    FileNotFound,
    InvalidFormat,
    PasswordRequired,
    NoPrivateKey,
    NonExportableKey,
    UnsupportedAlgorithm
}
