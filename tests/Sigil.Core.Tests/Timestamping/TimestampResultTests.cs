using Sigil.Timestamping;

namespace Sigil.Core.Tests.Timestamping;

public class TimestampResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = TimestampResult<byte[]>.Ok([1, 2, 3]);

        Assert.True(result.IsSuccess);
        Assert.Equal([1, 2, 3], result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = TimestampResult<byte[]>.Fail(TimestampErrorKind.Timeout, "timed out");

        Assert.False(result.IsSuccess);
        Assert.Equal(TimestampErrorKind.Timeout, result.ErrorKind);
        Assert.Equal("timed out", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = TimestampResult<int>.Fail(TimestampErrorKind.NetworkError, "error");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = TimestampResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = TimestampResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void All_error_kinds_are_distinct()
    {
        var kinds = Enum.GetValues<TimestampErrorKind>();

        Assert.True(kinds.Length >= 7);
        Assert.Equal(kinds.Length, kinds.Distinct().Count());
    }
}
