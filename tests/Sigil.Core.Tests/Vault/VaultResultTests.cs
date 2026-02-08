using Sigil.Vault;

namespace Sigil.Core.Tests.Vault;

public class VaultResultTests
{
    [Fact]
    public void Ok_ReturnsSuccessResult()
    {
        var result = VaultResult<string>.Ok("test-value");

        Assert.True(result.IsSuccess);
        Assert.Equal("test-value", result.Value);
    }

    [Fact]
    public void Fail_ReturnsFailedResult()
    {
        var result = VaultResult<string>.Fail(VaultErrorKind.AuthenticationFailed, "bad creds");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.AuthenticationFailed, result.ErrorKind);
        Assert.Equal("bad creds", result.ErrorMessage);
    }

    [Fact]
    public void Value_OnFailedResult_Throws()
    {
        var result = VaultResult<int>.Fail(VaultErrorKind.KeyNotFound, "not found");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_OnSuccessResult_Throws()
    {
        var result = VaultResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_OnSuccessResult_Throws()
    {
        var result = VaultResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Theory]
    [InlineData(VaultErrorKind.AuthenticationFailed)]
    [InlineData(VaultErrorKind.KeyNotFound)]
    [InlineData(VaultErrorKind.AccessDenied)]
    [InlineData(VaultErrorKind.UnsupportedAlgorithm)]
    [InlineData(VaultErrorKind.NetworkError)]
    [InlineData(VaultErrorKind.Timeout)]
    [InlineData(VaultErrorKind.ConfigurationError)]
    [InlineData(VaultErrorKind.SigningFailed)]
    [InlineData(VaultErrorKind.InvalidKeyReference)]
    public void Fail_AllErrorKinds_Supported(VaultErrorKind errorKind)
    {
        var result = VaultResult<string>.Fail(errorKind, "error");

        Assert.False(result.IsSuccess);
        Assert.Equal(errorKind, result.ErrorKind);
    }
}
