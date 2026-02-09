namespace Sigil.Transparency;

public enum TransparencyErrorKind
{
    LogNotFound,
    CheckpointNotFound,
    CheckpointMismatch,
    InvalidEntry,
    IntegrityViolation,
    DuplicateEntry,
    SerializationFailed,
    DeserializationFailed,
    AppendFailed,
    ProofVerificationFailed,
    InvalidProof,
    EnvelopeNotFound,
    InvalidEnvelope
}
