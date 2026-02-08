namespace Sigil.Timestamping;

public enum TimestampErrorKind
{
    NetworkError,
    Timeout,
    InvalidResponse,
    HashMismatch,
    InvalidToken,
    CertificateError,
    TsaRejected
}
