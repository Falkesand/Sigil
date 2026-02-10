namespace Sigil.Transparency.Remote;

public enum RemoteLogErrorKind
{
    NetworkError,
    Timeout,
    ServerError,
    AuthenticationFailed,
    DuplicateEntry,
    InvalidResponse,
    InvalidProof,
    InvalidCheckpoint,
    UnsupportedLogType,
    HttpsRequired
}
