namespace Sigil.Trust;

public enum TrustDecision
{
    Trusted,
    TrustedViaEndorsement,
    Untrusted,
    Expired,
    ScopeMismatch,
    BundleInvalid,
    Revoked
}
