namespace Sigil.Cli.Commands;

public enum PemLoadErrorKind
{
    FileNotFound,
    UnknownAlgorithm,
    PassphraseRequired,
    CryptoError
}
