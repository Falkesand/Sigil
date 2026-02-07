using Secure.Sbom.Crypto;

namespace Secure.Sbom.Keys;

/// <summary>
/// A key fingerprint is the SHA-256 hash of the SubjectPublicKeyInfo (SPKI) encoding.
/// Format: "sha256:hexdigest"
/// </summary>
public readonly struct KeyFingerprint : IEquatable<KeyFingerprint>
{
    public string Value { get; }

    private KeyFingerprint(string value)
    {
        Value = value;
    }

    public static KeyFingerprint Compute(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var hash = HashAlgorithms.Sha256Hex(spki);
        return new KeyFingerprint($"sha256:{hash}");
    }

    public static KeyFingerprint Parse(string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);

        if (!fingerprint.StartsWith("sha256:", StringComparison.Ordinal))
            throw new FormatException("Fingerprint must start with 'sha256:'.");

        var hex = fingerprint["sha256:".Length..];
        if (hex.Length != 64 || !hex.All(IsHexChar))
            throw new FormatException("Fingerprint must contain a 64-character hex digest after 'sha256:'.");

        return new KeyFingerprint(fingerprint);
    }

    public string ShortId => Value.Length > 20 ? Value[..20] : Value;

    public bool Equals(KeyFingerprint other) => string.Equals(Value, other.Value, StringComparison.Ordinal);
    public override bool Equals(object? obj) => obj is KeyFingerprint other && Equals(other);
    public override int GetHashCode() => Value?.GetHashCode(StringComparison.Ordinal) ?? 0;
    public override string ToString() => Value;

    public static bool operator ==(KeyFingerprint left, KeyFingerprint right) => left.Equals(right);
    public static bool operator !=(KeyFingerprint left, KeyFingerprint right) => !left.Equals(right);

    private static bool IsHexChar(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
