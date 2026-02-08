namespace Sigil.Vault.Pkcs11;

/// <summary>
/// Parses PKCS#11 URIs per RFC 7512, plus a legacy library-path format.
/// </summary>
/// <remarks>
/// Supported formats:
/// <list type="bullet">
///   <item>RFC 7512: <c>pkcs11:token=MyToken;object=my-key?module-path=/lib/p11.so&amp;pin-value=1234</c></item>
///   <item>Legacy: <c>/path/to/lib.so;token=MyToken;object=my-key</c></item>
/// </list>
/// </remarks>
public static class Pkcs11UriParser
{
    private const string Pkcs11Scheme = "pkcs11:";

    public static VaultResult<Pkcs11UriComponents> Parse(string uri)
    {
        if (string.IsNullOrEmpty(uri))
            return VaultResult<Pkcs11UriComponents>.Fail(
                VaultErrorKind.InvalidKeyReference,
                "PKCS#11 URI must not be null or empty.");

        if (uri.StartsWith(Pkcs11Scheme, StringComparison.OrdinalIgnoreCase))
            return ParseRfc7512(uri[Pkcs11Scheme.Length..]);

        if (IsLegacyFormat(uri))
            return ParseLegacy(uri);

        return VaultResult<Pkcs11UriComponents>.Fail(
            VaultErrorKind.InvalidKeyReference,
            "PKCS#11 URI must start with 'pkcs11:' or be a library path with semicolon-delimited attributes.");
    }

    private static VaultResult<Pkcs11UriComponents> ParseRfc7512(string body)
    {
        // Split on '?' to separate path attributes from query attributes
        var queryIndex = body.IndexOf('?');
        var pathPart = queryIndex >= 0 ? body[..queryIndex] : body;
        var queryPart = queryIndex >= 0 ? body[(queryIndex + 1)..] : null;

        var components = new Pkcs11UriComponents();

        if (!string.IsNullOrEmpty(pathPart))
            components = ApplyPathAttributes(components, pathPart);

        if (!string.IsNullOrEmpty(queryPart))
            components = ApplyQueryAttributes(components, queryPart);

        return VaultResult<Pkcs11UriComponents>.Ok(components);
    }

    private static Pkcs11UriComponents ApplyPathAttributes(Pkcs11UriComponents components, string pathPart)
    {
        foreach (var pair in pathPart.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex < 0)
                continue;

            var key = pair[..eqIndex].Trim();
            var value = PercentDecode(pair[(eqIndex + 1)..]);

            components = key.ToLowerInvariant() switch
            {
                "token" => components with { Token = value },
                "object" => components with { ObjectLabel = value },
                "type" => components with { Type = value },
                "id" => components with { Id = PercentDecodeBytes(pair[(eqIndex + 1)..]) },
                "slot-id" when ulong.TryParse(value, out var slotId) => components with { SlotId = slotId },
                "manufacturer" => components with { Manufacturer = value },
                "serial" => components with { Serial = value },
                _ => components
            };
        }

        return components;
    }

    private static Pkcs11UriComponents ApplyQueryAttributes(Pkcs11UriComponents components, string queryPart)
    {
        foreach (var pair in queryPart.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex < 0)
                continue;

            var key = pair[..eqIndex].Trim();
            var value = PercentDecode(pair[(eqIndex + 1)..]);

            components = key.ToLowerInvariant() switch
            {
                "module-path" => components with { ModulePath = value },
                "pin-value" => components with { PinValue = value },
                _ => components
            };
        }

        return components;
    }

    private static bool IsLegacyFormat(string uri)
    {
        // Legacy format starts with a file path (Unix / or Windows drive letter)
        // and contains semicolons with key=value pairs
        if (uri.Length < 2)
            return false;

        var startsWithPath = uri[0] == '/' || (char.IsLetter(uri[0]) && uri[1] == ':');
        return startsWithPath && uri.Contains(';');
    }

    private static VaultResult<Pkcs11UriComponents> ParseLegacy(string uri)
    {
        // Format: /path/to/lib.so;token=X;object=Y
        // or: C:\path\lib.dll;token=X;object=Y
        var firstSemicolon = uri.IndexOf(';');
        var libraryPath = uri[..firstSemicolon];
        var remainder = uri[(firstSemicolon + 1)..];

        var components = new Pkcs11UriComponents { ModulePath = libraryPath };
        components = ApplyPathAttributes(components, remainder);

        return VaultResult<Pkcs11UriComponents>.Ok(components);
    }

    private static string PercentDecode(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }

    /// <summary>
    /// Decodes percent-encoded binary data (e.g., key IDs like %01%02%FF).
    /// Parses hex bytes directly rather than going through Uri.UnescapeDataString,
    /// which would corrupt bytes above 0x7F via UTF-8 decoding.
    /// </summary>
    private static byte[] PercentDecodeBytes(string value)
    {
        var result = new List<byte>();
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '%' && i + 2 < value.Length
                && byte.TryParse(value.AsSpan(i + 1, 2),
                    System.Globalization.NumberStyles.HexNumber, null, out var b))
            {
                result.Add(b);
                i += 2;
            }
            else
            {
                result.Add((byte)value[i]);
            }
        }
        return result.ToArray();
    }
}
