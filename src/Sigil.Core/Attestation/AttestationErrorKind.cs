namespace Sigil.Attestation;

public enum AttestationErrorKind
{
    InvalidPayloadType,
    DeserializationFailed,
    SerializationFailed,
    SigningFailed,
    VerificationFailed,
    DigestMismatch,
    InvalidStatement,
    InvalidPredicateType,
    SubjectMissing,
    FileNotFound
}
