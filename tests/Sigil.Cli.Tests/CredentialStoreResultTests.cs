using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests;

public class CredentialStoreResultTests
{
    [Fact]
    public void Ok_IsSuccess_True()
    {
        var result = CredentialStoreResult<string>.Ok("secret");

        Assert.True(result.IsSuccess);
        Assert.Equal("secret", result.Value);
    }

    [Fact]
    public void Fail_IsSuccess_False()
    {
        var result = CredentialStoreResult<string>.Fail(
            CredentialStoreErrorKind.NotFound, "Credential not found.");

        Assert.False(result.IsSuccess);
        Assert.Equal(CredentialStoreErrorKind.NotFound, result.ErrorKind);
        Assert.Equal("Credential not found.", result.ErrorMessage);
    }

    [Fact]
    public void Ok_AccessErrorKind_Throws()
    {
        var result = CredentialStoreResult<string>.Ok("secret");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void Fail_AccessValue_Throws()
    {
        var result = CredentialStoreResult<string>.Fail(
            CredentialStoreErrorKind.AccessDenied, "Access denied.");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void Ok_AccessErrorMessage_Throws()
    {
        var result = CredentialStoreResult<string>.Ok("secret");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }
}
