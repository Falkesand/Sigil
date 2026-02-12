namespace Sigil.Pe;

public enum AuthenticodeErrorKind
{
    InvalidPeFormat,
    NotPortableExecutable,
    NoCertificate,
    SigningFailed,
    VerificationFailed,
    UnsupportedAlgorithm,
    InvalidSignature,
    NoSignatureFound,
    TimestampFailed
}
