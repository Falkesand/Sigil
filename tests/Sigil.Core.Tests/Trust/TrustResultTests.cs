using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = TrustResult<int>.Ok(42);

        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = TrustResult<int>.Fail(TrustErrorKind.BundleInvalid, "bad bundle");

        Assert.False(result.IsSuccess);
        Assert.Equal(TrustErrorKind.BundleInvalid, result.ErrorKind);
        Assert.Equal("bad bundle", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = TrustResult<int>.Fail(TrustErrorKind.DeserializationFailed, "parse error");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = TrustResult<string>.Ok("hello");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = TrustResult<string>.Ok("hello");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void Ok_with_null_value_is_still_success()
    {
        var result = TrustResult<string?>.Ok(null);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value);
    }
}
