namespace Sigil.Trust;

public enum TrustDecision
{
    Trusted,
    TrustedViaEndorsement,
    TrustedViaOidc,
    Untrusted,
    Expired,
    ScopeMismatch,
    BundleInvalid,
    Revoked
}
