using System.Text;

namespace Sigil.Git;

/// <summary>
/// Wraps and unwraps Sigil signature envelope JSON in ASCII armor
/// for git's x509 signature format.
/// </summary>
public static class GitSignatureArmor
{
    private const string BeginMarker = "-----BEGIN SIGNED MESSAGE-----";
    private const string EndMarker = "-----END SIGNED MESSAGE-----";

    /// <summary>
    /// Wraps envelope JSON in ASCII armor with base64 encoding.
    /// </summary>
    public static string Wrap(string envelopeJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(envelopeJson);

        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(envelopeJson));

        var sb = new StringBuilder();
        sb.AppendLine(BeginMarker);

        // Split base64 into 76-char lines per RFC 4648
        for (int i = 0; i < base64.Length; i += 76)
        {
            int length = Math.Min(76, base64.Length - i);
            sb.AppendLine(base64.Substring(i, length));
        }

        sb.Append(EndMarker);
        return sb.ToString();
    }

    /// <summary>
    /// Unwraps ASCII armor to recover the original envelope JSON.
    /// </summary>
    public static GitResult<string> Unwrap(string armored)
    {
        if (string.IsNullOrWhiteSpace(armored))
            return GitResult<string>.Fail(GitErrorKind.InvalidArmor, "Armored text is empty.");

        int beginIndex = armored.IndexOf(BeginMarker, StringComparison.Ordinal);
        if (beginIndex < 0)
            return GitResult<string>.Fail(GitErrorKind.InvalidArmor, "Missing BEGIN SIGNED MESSAGE marker.");

        int endIndex = armored.IndexOf(EndMarker, StringComparison.Ordinal);
        if (endIndex < 0)
            return GitResult<string>.Fail(GitErrorKind.InvalidArmor, "Missing END SIGNED MESSAGE marker.");

        int contentStart = beginIndex + BeginMarker.Length;
        if (contentStart >= endIndex)
            return GitResult<string>.Fail(GitErrorKind.InvalidArmor, "No content between armor markers.");

        var base64Content = armored[contentStart..endIndex].Trim();
        if (base64Content.Length == 0)
            return GitResult<string>.Fail(GitErrorKind.InvalidArmor, "No content between armor markers.");

        // Remove whitespace/newlines from base64 block
        var cleanBase64 = new StringBuilder(base64Content.Length);
        foreach (char c in base64Content)
        {
            if (!char.IsWhiteSpace(c))
                cleanBase64.Append(c);
        }

        try
        {
            var bytes = Convert.FromBase64String(cleanBase64.ToString());
            var json = Encoding.UTF8.GetString(bytes);
            return GitResult<string>.Ok(json);
        }
        catch (FormatException)
        {
            return GitResult<string>.Fail(GitErrorKind.InvalidArmor, "Invalid base64 content in armor.");
        }
    }

    /// <summary>
    /// Checks whether text contains a Sigil signature armor block.
    /// </summary>
    public static bool ContainsArmor(string text)
    {
        return !string.IsNullOrEmpty(text)
            && text.Contains(BeginMarker, StringComparison.Ordinal)
            && text.Contains(EndMarker, StringComparison.Ordinal);
    }
}
