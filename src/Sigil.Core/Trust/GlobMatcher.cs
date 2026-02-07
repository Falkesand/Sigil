namespace Sigil.Trust;

/// <summary>
/// Simple glob pattern matcher supporting * (any chars) and ? (single char).
/// Case-insensitive.
/// </summary>
public static class GlobMatcher
{
    public static bool IsMatch(ReadOnlySpan<char> input, ReadOnlySpan<char> pattern)
    {
        int i = 0, p = 0;
        int starIdx = -1, matchIdx = 0;

        while (i < input.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || CharsEqual(input[i], pattern[p])))
            {
                i++;
                p++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                starIdx = p;
                matchIdx = i;
                p++;
            }
            else if (starIdx >= 0)
            {
                p = starIdx + 1;
                matchIdx++;
                i = matchIdx;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
            p++;

        return p == pattern.Length;
    }

    private static bool CharsEqual(char a, char b) =>
        char.ToLowerInvariant(a) == char.ToLowerInvariant(b);
}
