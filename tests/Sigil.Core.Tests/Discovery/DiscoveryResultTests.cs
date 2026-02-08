using Sigil.Discovery;

namespace Sigil.Core.Tests.Discovery;

public class DiscoveryResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = DiscoveryResult<string>.Ok("bundle json");

        Assert.True(result.IsSuccess);
        Assert.Equal("bundle json", result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = DiscoveryResult<string>.Fail(DiscoveryErrorKind.NotFound, "not found");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.NotFound, result.ErrorKind);
        Assert.Equal("not found", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = DiscoveryResult<int>.Fail(DiscoveryErrorKind.NetworkError, "timeout");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = DiscoveryResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = DiscoveryResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void All_error_kinds_are_distinct()
    {
        var kinds = Enum.GetValues<DiscoveryErrorKind>();

        Assert.True(kinds.Length >= 7);
        Assert.Equal(kinds.Length, kinds.Distinct().Count());
    }
}
