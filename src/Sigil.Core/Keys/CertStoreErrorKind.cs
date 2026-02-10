namespace Sigil.Keys;

public enum CertStoreErrorKind
{
    CertificateNotFound,
    NoPrivateKey,
    UnsupportedAlgorithm,
    PlatformNotSupported,
    StoreAccessDenied
}
