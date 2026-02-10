using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class KeylessResultTests
{
    [Fact]
    public void Ok_ReturnsSuccessResult()
    {
        var result = KeylessResult<string>.Ok("test-value");

        Assert.True(result.IsSuccess);
        Assert.Equal("test-value", result.Value);
    }

    [Fact]
    public void Fail_ReturnsFailedResult()
    {
        var result = KeylessResult<string>.Fail(KeylessErrorKind.TokenParsingFailed, "bad token");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenParsingFailed, result.ErrorKind);
        Assert.Equal("bad token", result.ErrorMessage);
    }

    [Fact]
    public void Value_OnFailedResult_Throws()
    {
        var result = KeylessResult<int>.Fail(KeylessErrorKind.NetworkError, "network error");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_OnSuccessResult_Throws()
    {
        var result = KeylessResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Theory]
    [InlineData(KeylessErrorKind.TokenAcquisitionFailed)]
    [InlineData(KeylessErrorKind.TokenParsingFailed)]
    [InlineData(KeylessErrorKind.TokenValidationFailed)]
    [InlineData(KeylessErrorKind.JwksFetchFailed)]
    [InlineData(KeylessErrorKind.AudienceMismatch)]
    [InlineData(KeylessErrorKind.TokenExpired)]
    [InlineData(KeylessErrorKind.UnsupportedAlgorithm)]
    [InlineData(KeylessErrorKind.NetworkError)]
    [InlineData(KeylessErrorKind.TimestampRequired)]
    [InlineData(KeylessErrorKind.ConfigurationError)]
    public void Fail_AllErrorKinds_Supported(KeylessErrorKind errorKind)
    {
        var result = KeylessResult<string>.Fail(errorKind, "error");

        Assert.False(result.IsSuccess);
        Assert.Equal(errorKind, result.ErrorKind);
    }
}
