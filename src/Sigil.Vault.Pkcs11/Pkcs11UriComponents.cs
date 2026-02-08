namespace Sigil.Vault.Pkcs11;

/// <summary>
/// Parsed components of a PKCS#11 URI (RFC 7512).
/// </summary>
public sealed record Pkcs11UriComponents
{
    /// <summary>Path to the PKCS#11 shared library (.so/.dll).</summary>
    public string? ModulePath { get; init; }

    /// <summary>Token label to match.</summary>
    public string? Token { get; init; }

    /// <summary>Key object label to find.</summary>
    public string? ObjectLabel { get; init; }

    /// <summary>Key object ID (binary).</summary>
    public byte[]? Id { get; init; }

    /// <summary>Object type filter: "private", "public", "cert", etc.</summary>
    public string? Type { get; init; }

    /// <summary>Slot ID number.</summary>
    public ulong? SlotId { get; init; }

    /// <summary>Token manufacturer.</summary>
    public string? Manufacturer { get; init; }

    /// <summary>Token serial number.</summary>
    public string? Serial { get; init; }

    /// <summary>PIN value for authentication.</summary>
    public string? PinValue { get; init; }
}
