namespace Sigil.Trust;

/// <summary>
/// Matches artifact properties against trust scopes.
/// Null scopes or null scope lists mean unrestricted.
/// </summary>
public static class ScopeMatcher
{
    /// <summary>
    /// Returns true if the given artifact properties satisfy the scope constraints.
    /// Null values for artifactName/label/algorithm skip that dimension's check.
    /// </summary>
    public static bool Matches(TrustScopes? scopes, string? artifactName, string? label, string? algorithm)
    {
        if (scopes is null)
            return true;

        if (artifactName is not null
            && scopes.NamePatterns is { Count: > 0 }
            && !scopes.NamePatterns.Any(p => GlobMatcher.IsMatch(artifactName, p)))
        {
            return false;
        }

        if (label is not null
            && scopes.Labels is { Count: > 0 }
            && !scopes.Labels.Contains(label, StringComparer.Ordinal))
        {
            return false;
        }

        if (algorithm is not null
            && scopes.Algorithms is { Count: > 0 }
            && !scopes.Algorithms.Contains(algorithm, StringComparer.Ordinal))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Combines two sets of scopes. Merges each dimension's list.
    /// Used when an endorsement has its own scopes on top of the key's scopes.
    /// </summary>
    public static TrustScopes? Intersect(TrustScopes? a, TrustScopes? b)
    {
        if (a is null && b is null)
            return null;
        if (a is null)
            return b;
        if (b is null)
            return a;

        return new TrustScopes
        {
            NamePatterns = MergeLists(a.NamePatterns, b.NamePatterns),
            Labels = MergeLists(a.Labels, b.Labels),
            Algorithms = MergeLists(a.Algorithms, b.Algorithms)
        };
    }

    private static List<string>? MergeLists(List<string>? a, List<string>? b)
    {
        if (a is null or { Count: 0 } && b is null or { Count: 0 })
            return null;
        if (a is null or { Count: 0 })
            return [.. b!];
        if (b is null or { Count: 0 })
            return [.. a];

        var merged = new List<string>(a.Count + b.Count);
        merged.AddRange(a);
        merged.AddRange(b);
        return merged;
    }
}
