using System.Text.Json;

namespace Sigil.Keyless;

public sealed class JwtToken
{
    public required string RawToken { get; init; }
    public required JsonElement Header { get; init; }
    public required JsonElement Payload { get; init; }
    public required byte[] SignatureBytes { get; init; }
    public required string SigningInput { get; init; }

    public string? Algorithm => Header.TryGetProperty("alg", out var v) ? v.GetString() : null;
    public string? KeyId => Header.TryGetProperty("kid", out var v) ? v.GetString() : null;
    public string? Issuer => Payload.TryGetProperty("iss", out var v) ? v.GetString() : null;
    public string? Subject => Payload.TryGetProperty("sub", out var v) ? v.GetString() : null;
    public long? ExpirationUnix => Payload.TryGetProperty("exp", out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : null;
    public string? Audience { get; init; }
}
