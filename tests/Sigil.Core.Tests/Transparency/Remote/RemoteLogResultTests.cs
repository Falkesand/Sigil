using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class RemoteLogResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = RemoteLogResult<string>.Ok("receipt");

        Assert.True(result.IsSuccess);
        Assert.Equal("receipt", result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = RemoteLogResult<string>.Fail(
            RemoteLogErrorKind.NetworkError, "connection refused");

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.NetworkError, result.ErrorKind);
        Assert.Equal("connection refused", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = RemoteLogResult<int>.Fail(RemoteLogErrorKind.Timeout, "timed out");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = RemoteLogResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = RemoteLogResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Theory]
    [InlineData(RemoteLogErrorKind.NetworkError)]
    [InlineData(RemoteLogErrorKind.Timeout)]
    [InlineData(RemoteLogErrorKind.ServerError)]
    [InlineData(RemoteLogErrorKind.AuthenticationFailed)]
    [InlineData(RemoteLogErrorKind.DuplicateEntry)]
    [InlineData(RemoteLogErrorKind.InvalidResponse)]
    [InlineData(RemoteLogErrorKind.InvalidProof)]
    [InlineData(RemoteLogErrorKind.InvalidCheckpoint)]
    [InlineData(RemoteLogErrorKind.UnsupportedLogType)]
    [InlineData(RemoteLogErrorKind.HttpsRequired)]
    public void All_error_kinds_can_be_used(RemoteLogErrorKind kind)
    {
        var result = RemoteLogResult<bool>.Fail(kind, "test");

        Assert.Equal(kind, result.ErrorKind);
    }
}
