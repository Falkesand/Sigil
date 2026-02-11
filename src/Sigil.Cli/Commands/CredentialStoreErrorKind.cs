namespace Sigil.Cli.Commands;

public enum CredentialStoreErrorKind
{
    NotFound,
    AccessDenied,
    PlatformNotSupported,
    InvalidTarget,
    StoreFailed,
    DeleteFailed
}
