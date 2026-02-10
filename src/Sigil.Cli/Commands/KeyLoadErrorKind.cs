namespace Sigil.Cli.Commands;

public enum KeyLoadErrorKind
{
    FileNotFound,
    UnknownAlgorithm,
    PassphraseRequired,
    CryptoError,
    UnsupportedFormat
}
