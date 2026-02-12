using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphResultTests
{
    [Fact]
    public void Ok_returns_success_with_value()
    {
        var result = GraphResult<string>.Ok("hello");

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
    }

    [Fact]
    public void Ok_returns_success_with_int_value()
    {
        var result = GraphResult<int>.Ok(42);

        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void Fail_returns_failure_with_error()
    {
        var result = GraphResult<int>.Fail(GraphErrorKind.NodeNotFound, "node missing");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
        Assert.Equal("node missing", result.ErrorMessage);
    }

    [Fact]
    public void Value_on_failure_throws()
    {
        var result = GraphResult<int>.Fail(GraphErrorKind.InvalidEdge, "bad edge");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ErrorKind_on_success_throws()
    {
        var result = GraphResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void ErrorMessage_on_success_throws()
    {
        var result = GraphResult<string>.Ok("data");

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void Ok_with_null_value_succeeds()
    {
        var result = GraphResult<string?>.Ok(null);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value);
    }

    [Fact]
    public void Fail_preserves_all_error_kinds()
    {
        foreach (var kind in Enum.GetValues<GraphErrorKind>())
        {
            var result = GraphResult<string>.Fail(kind, $"Error: {kind}");
            Assert.Equal(kind, result.ErrorKind);
        }
    }
}
