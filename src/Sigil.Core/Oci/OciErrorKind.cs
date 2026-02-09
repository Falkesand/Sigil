namespace Sigil.Oci;

/// <summary>
/// Error kinds for OCI registry operations.
/// </summary>
public enum OciErrorKind
{
    NetworkError,
    Timeout,
    AuthenticationFailed,
    ManifestNotFound,
    InvalidReference,
    InvalidManifest,
    BlobUploadFailed,
    ReferrersNotSupported,
    RegistryError,
    SignatureNotFound
}
