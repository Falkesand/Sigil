namespace Sigil.Vault;

public enum VaultErrorKind
{
    AuthenticationFailed,
    KeyNotFound,
    AccessDenied,
    UnsupportedAlgorithm,
    NetworkError,
    Timeout,
    ConfigurationError,
    SigningFailed,
    InvalidKeyReference
}
