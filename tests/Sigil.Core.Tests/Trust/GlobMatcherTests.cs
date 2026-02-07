using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class GlobMatcherTests
{
    [Theory]
    [InlineData("hello", "hello", true)]
    [InlineData("hello", "world", false)]
    [InlineData("", "", true)]
    public void Exact_match(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, GlobMatcher.IsMatch(input, pattern));
    }

    [Theory]
    [InlineData("file.tar.gz", "*.tar.gz", true)]
    [InlineData("archive.zip", "*.zip", true)]
    [InlineData("archive.tar", "*.zip", false)]
    [InlineData("anything", "*", true)]
    [InlineData("", "*", true)]
    [InlineData("abc", "a*c", true)]
    [InlineData("ac", "a*c", true)]
    [InlineData("abxyzc", "a*c", true)]
    [InlineData("abxyz", "a*c", false)]
    public void Star_wildcard(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, GlobMatcher.IsMatch(input, pattern));
    }

    [Theory]
    [InlineData("a", "?", true)]
    [InlineData("ab", "?b", true)]
    [InlineData("ab", "a?", true)]
    [InlineData("abc", "a?c", true)]
    [InlineData("ac", "a?c", false)]
    [InlineData("", "?", false)]
    public void Question_mark_wildcard(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, GlobMatcher.IsMatch(input, pattern));
    }

    [Theory]
    [InlineData("file.tar.gz", "*.tar.*", true)]
    [InlineData("x.tar.bz2", "*.tar.*", true)]
    [InlineData("file.zip", "*.tar.*", false)]
    [InlineData("abc", "a?c", true)]
    [InlineData("aXYZc", "a*?c", true)]
    public void Combined_wildcards(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, GlobMatcher.IsMatch(input, pattern));
    }

    [Theory]
    [InlineData("FILE.TAR.GZ", "*.tar.gz", true)]
    [InlineData("Hello", "hello", true)]
    [InlineData("HELLO", "hello", true)]
    public void Case_insensitive(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, GlobMatcher.IsMatch(input, pattern));
    }

    [Theory]
    [InlineData("abc", "**", true)]
    [InlineData("abc", "a**c", true)]
    public void Multiple_consecutive_stars(string input, string pattern, bool expected)
    {
        Assert.Equal(expected, GlobMatcher.IsMatch(input, pattern));
    }
}
