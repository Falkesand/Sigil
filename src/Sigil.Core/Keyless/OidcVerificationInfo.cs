namespace Sigil.Keyless;

public sealed class OidcVerificationInfo
{
    public required bool IsValid { get; init; }
    public string? Issuer { get; init; }
    public string? Identity { get; init; }
    public string? Error { get; init; }
}
