namespace Sigil.Trust;

public enum TrustErrorKind
{
    BundleInvalid,
    DeserializationFailed,
    SignatureVerificationFailed,
    KeyNotFound,
    AuthorityMismatch,
    SerializationFailed
}
