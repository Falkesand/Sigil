using Sigil.Policy;

namespace Sigil.Core.Tests.Policy;

public class PolicyResultTests
{
    [Fact]
    public void Ok_IsSuccess_ReturnsTrue()
    {
        var result = PolicyResult<int>.Ok(42);

        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void Fail_IsSuccess_ReturnsFalse()
    {
        var result = PolicyResult<int>.Fail(PolicyErrorKind.InvalidPolicy, "bad");

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Equal("bad", result.ErrorMessage);
    }

    [Fact]
    public void Ok_AccessErrorKind_Throws()
    {
        var result = PolicyResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void Ok_AccessErrorMessage_Throws()
    {
        var result = PolicyResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void Fail_AccessValue_Throws()
    {
        var result = PolicyResult<int>.Fail(PolicyErrorKind.EvaluationFailed, "eval");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void Fail_AllErrorKinds_Roundtrip()
    {
        foreach (var kind in Enum.GetValues<PolicyErrorKind>())
        {
            var result = PolicyResult<string>.Fail(kind, $"Error: {kind}");
            Assert.Equal(kind, result.ErrorKind);
        }
    }
}
