namespace Sigil.Git;

public enum GitErrorKind
{
    InvalidArmor,
    InvalidEnvelope,
    SigningFailed,
    VerificationFailed,
    KeyNotFound,
    InvalidArguments,
    IoError
}
