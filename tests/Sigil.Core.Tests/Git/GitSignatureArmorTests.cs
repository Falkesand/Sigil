using Sigil.Git;

namespace Sigil.Core.Tests.Git;

public class GitSignatureArmorTests
{
    private const string SampleJson = """{"version":"1.0","subject":{"name":"test"}}""";

    [Fact]
    public void Wrap_produces_valid_armor_with_markers()
    {
        var armored = GitSignatureArmor.Wrap(SampleJson);

        Assert.StartsWith("-----BEGIN SIGNED MESSAGE-----", armored);
        Assert.EndsWith("-----END SIGNED MESSAGE-----", armored);
    }

    [Fact]
    public void Unwrap_recovers_original_json()
    {
        var armored = GitSignatureArmor.Wrap(SampleJson);

        var result = GitSignatureArmor.Unwrap(armored);

        Assert.True(result.IsSuccess);
        Assert.Equal(SampleJson, result.Value);
    }

    [Fact]
    public void Roundtrip_preserves_content()
    {
        var largeJson = new string('x', 1000);
        var armored = GitSignatureArmor.Wrap(largeJson);

        var result = GitSignatureArmor.Unwrap(armored);

        Assert.True(result.IsSuccess);
        Assert.Equal(largeJson, result.Value);
    }

    [Fact]
    public void Unwrap_fails_on_missing_begin_marker()
    {
        var result = GitSignatureArmor.Unwrap("some random text\n-----END SIGNED MESSAGE-----");

        Assert.False(result.IsSuccess);
        Assert.Equal(GitErrorKind.InvalidArmor, result.ErrorKind);
        Assert.Contains("BEGIN", result.ErrorMessage);
    }

    [Fact]
    public void Unwrap_fails_on_missing_end_marker()
    {
        var result = GitSignatureArmor.Unwrap("-----BEGIN SIGNED MESSAGE-----\ndata");

        Assert.False(result.IsSuccess);
        Assert.Equal(GitErrorKind.InvalidArmor, result.ErrorKind);
        Assert.Contains("END", result.ErrorMessage);
    }

    [Fact]
    public void Unwrap_fails_on_empty_content()
    {
        var result = GitSignatureArmor.Unwrap("-----BEGIN SIGNED MESSAGE-----\n-----END SIGNED MESSAGE-----");

        Assert.False(result.IsSuccess);
        Assert.Equal(GitErrorKind.InvalidArmor, result.ErrorKind);
    }

    [Fact]
    public void ContainsArmor_returns_true_for_valid_armor()
    {
        var armored = GitSignatureArmor.Wrap(SampleJson);

        Assert.True(GitSignatureArmor.ContainsArmor(armored));
        Assert.False(GitSignatureArmor.ContainsArmor("no armor here"));
        Assert.False(GitSignatureArmor.ContainsArmor(""));
    }
}
