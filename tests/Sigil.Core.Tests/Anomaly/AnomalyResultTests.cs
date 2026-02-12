using Sigil.Anomaly;

namespace Sigil.Core.Tests.Anomaly;

public class AnomalyResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = AnomalyResult<string>.Ok("hello");

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = AnomalyResult<int>.Fail(AnomalyErrorKind.BaselineNotFound, "baseline missing");

        Assert.False(result.IsSuccess);
        Assert.Equal(AnomalyErrorKind.BaselineNotFound, result.ErrorKind);
        Assert.Equal("baseline missing", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = AnomalyResult<int>.Fail(AnomalyErrorKind.BaselineCorrupt, "corrupt data");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = AnomalyResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = AnomalyResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void Ok_with_null_value_succeeds()
    {
        var result = AnomalyResult<string?>.Ok(null);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value);
    }

    [Fact]
    public void Fail_preserves_all_error_kinds()
    {
        foreach (var kind in Enum.GetValues<AnomalyErrorKind>())
        {
            var result = AnomalyResult<string>.Fail(kind, $"Error: {kind}");
            Assert.Equal(kind, result.ErrorKind);
        }
    }
}
