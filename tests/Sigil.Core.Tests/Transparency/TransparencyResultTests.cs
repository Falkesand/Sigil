using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class TransparencyResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = TransparencyResult<string>.Ok("logged");

        Assert.True(result.IsSuccess);
        Assert.Equal("logged", result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = TransparencyResult<string>.Fail(TransparencyErrorKind.DuplicateEntry, "already logged");

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.DuplicateEntry, result.ErrorKind);
        Assert.Equal("already logged", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = TransparencyResult<int>.Fail(TransparencyErrorKind.LogNotFound, "missing");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = TransparencyResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = TransparencyResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }
}
