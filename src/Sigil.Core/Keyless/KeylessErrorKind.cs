namespace Sigil.Keyless;

public enum KeylessErrorKind
{
    TokenAcquisitionFailed,
    TokenParsingFailed,
    TokenValidationFailed,
    JwksFetchFailed,
    AudienceMismatch,
    TokenExpired,
    UnsupportedAlgorithm,
    NetworkError,
    TimestampRequired,
    ConfigurationError
}
