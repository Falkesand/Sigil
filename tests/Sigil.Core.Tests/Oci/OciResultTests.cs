using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class OciResultTests
{
    [Fact]
    public void Ok_stores_value()
    {
        var result = OciResult<string>.Ok("hello");

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
    }

    [Fact]
    public void Ok_accessing_ErrorKind_throws()
    {
        var result = OciResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void Ok_accessing_ErrorMessage_throws()
    {
        var result = OciResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void Fail_stores_error()
    {
        var result = OciResult<string>.Fail(OciErrorKind.NetworkError, "connection refused");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.NetworkError, result.ErrorKind);
        Assert.Equal("connection refused", result.ErrorMessage);
    }

    [Fact]
    public void Fail_accessing_Value_throws()
    {
        var result = OciResult<string>.Fail(OciErrorKind.Timeout, "timed out");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void Fail_with_different_error_kinds()
    {
        var result = OciResult<int>.Fail(OciErrorKind.AuthenticationFailed, "401");

        Assert.Equal(OciErrorKind.AuthenticationFailed, result.ErrorKind);
    }
}
