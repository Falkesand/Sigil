using Sigil.Git;

namespace Sigil.Core.Tests.Git;

public class GitResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = GitResult<string>.Ok("signed");

        Assert.True(result.IsSuccess);
        Assert.Equal("signed", result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = GitResult<string>.Fail(GitErrorKind.InvalidArmor, "bad armor");

        Assert.False(result.IsSuccess);
        Assert.Equal(GitErrorKind.InvalidArmor, result.ErrorKind);
        Assert.Equal("bad armor", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = GitResult<int>.Fail(GitErrorKind.KeyNotFound, "missing");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = GitResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = GitResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }
}
