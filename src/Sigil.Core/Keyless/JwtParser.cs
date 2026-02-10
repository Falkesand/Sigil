using System.Text;
using System.Text.Json;

namespace Sigil.Keyless;

public static class JwtParser
{
    public static KeylessResult<JwtToken> Parse(string rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, "Token is null or empty.");
        }

        var parts = rawToken.Split('.');
        if (parts.Length != 3)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, $"Expected 3 parts, found {parts.Length}.");
        }

        byte[] headerBytes;
        byte[] payloadBytes;
        byte[] signatureBytes;

        try
        {
            headerBytes = Base64UrlDecode(parts[0]);
        }
        catch (FormatException)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, "Invalid base64url in header.");
        }

        try
        {
            payloadBytes = Base64UrlDecode(parts[1]);
        }
        catch (FormatException)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, "Invalid base64url in payload.");
        }

        try
        {
            signatureBytes = Base64UrlDecode(parts[2]);
        }
        catch (FormatException)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, "Invalid base64url in signature.");
        }

        JsonElement header;
        try
        {
            using var headerDoc = JsonDocument.Parse(headerBytes);
            header = headerDoc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, "Header is not valid JSON.");
        }

        JsonElement payload;
        try
        {
            using var payloadDoc = JsonDocument.Parse(payloadBytes);
            payload = payloadDoc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenParsingFailed, "Payload is not valid JSON.");
        }

        string? audience = null;
        if (payload.TryGetProperty("aud", out var audElement))
        {
            audience = audElement.ValueKind switch
            {
                JsonValueKind.String => audElement.GetString(),
                JsonValueKind.Array => audElement.GetArrayLength() > 0
                    ? audElement[0].GetString()
                    : null,
                _ => null
            };
        }

        var signingInput = parts[0] + "." + parts[1];

        var token = new JwtToken
        {
            RawToken = rawToken,
            Header = header,
            Payload = payload,
            SignatureBytes = signatureBytes,
            SigningInput = signingInput,
            Audience = audience
        };

        return KeylessResult<JwtToken>.Ok(token);
    }

    internal static byte[] Base64UrlDecode(string input)
    {
        var s = new StringBuilder(input);
        s.Replace('-', '+');
        s.Replace('_', '/');

        switch (s.Length % 4)
        {
            case 2: s.Append("=="); break;
            case 3: s.Append('='); break;
        }

        return Convert.FromBase64String(s.ToString());
    }

    internal static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
