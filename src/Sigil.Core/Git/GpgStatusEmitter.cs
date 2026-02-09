using System.Globalization;

namespace Sigil.Git;

/// <summary>
/// Generates GPG-compatible [GNUPG:] status messages
/// that git expects for --show-signature / verify-commit.
/// </summary>
public static class GpgStatusEmitter
{
    /// <summary>
    /// Emits SIG_CREATED status for signing operations.
    /// Format: [GNUPG:] SIG_CREATED D {algo} {hash} {class} {timestamp} {fingerprint}
    /// </summary>
    public static string SigCreated(string algorithm, string fingerprint, DateTimeOffset timestamp)
    {
        var ts = timestamp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        return $"[GNUPG:] SIG_CREATED D {algorithm} 8 00 {ts} {fingerprint}";
    }

    /// <summary>
    /// Emits GOODSIG status for successful verification.
    /// Format: [GNUPG:] GOODSIG {keyId} {keyId}
    /// </summary>
    public static string GoodSig(string keyId)
    {
        return $"[GNUPG:] GOODSIG {keyId} {keyId}";
    }

    /// <summary>
    /// Emits BADSIG status for failed verification.
    /// Format: [GNUPG:] BADSIG {keyId} {keyId}
    /// </summary>
    public static string BadSig(string keyId)
    {
        return $"[GNUPG:] BADSIG {keyId} {keyId}";
    }

    /// <summary>
    /// Emits VALIDSIG status with signature details.
    /// Format: [GNUPG:] VALIDSIG {fingerprint} {date} {timestamp} {expire} {version} 0 {algo} {hash} 00 {fingerprint}
    /// </summary>
    public static string ValidSig(string fingerprint, DateTimeOffset timestamp, string algorithm)
    {
        var ts = timestamp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var date = timestamp.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        return $"[GNUPG:] VALIDSIG {fingerprint} {date} {ts} 0 1.0 0 {algorithm} 8 00 {fingerprint}";
    }

    /// <summary>
    /// Emits TRUST_FULLY status indicating full trust.
    /// </summary>
    public static string TrustFully()
    {
        return "[GNUPG:] TRUST_FULLY 0 sigil";
    }

    /// <summary>
    /// Emits TRUST_UNDEFINED status indicating unknown trust.
    /// </summary>
    public static string TrustUndefined()
    {
        return "[GNUPG:] TRUST_UNDEFINED 0 sigil";
    }
}
