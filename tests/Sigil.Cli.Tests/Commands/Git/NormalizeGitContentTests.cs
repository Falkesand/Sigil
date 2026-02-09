using System.Text;
using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests.Commands.Git;

public class NormalizeGitContentTests
{
    [Fact]
    public void Strips_blank_line_between_headers_and_body()
    {
        var input = "tree abc123\nauthor Test\n\ncommit message\n"u8.ToArray();
        var result = GitSignProgram.NormalizeGitContent(input);

        Assert.Equal("tree abc123\nauthor Test\ncommit message\n", Encoding.UTF8.GetString(result));
    }

    [Fact]
    public void Content_without_blank_line_returned_unchanged()
    {
        var input = "tree abc123\nauthor Test\ncommit message\n"u8.ToArray();
        var result = GitSignProgram.NormalizeGitContent(input);

        Assert.Equal(input, result);
    }

    [Fact]
    public void Only_first_blank_line_is_stripped()
    {
        var input = "tree abc123\n\nfirst para\n\nsecond para\n"u8.ToArray();
        var result = GitSignProgram.NormalizeGitContent(input);

        Assert.Equal("tree abc123\nfirst para\n\nsecond para\n", Encoding.UTF8.GetString(result));
    }

    [Fact]
    public void Empty_content_returned_unchanged()
    {
        var result = GitSignProgram.NormalizeGitContent([]);
        Assert.Empty(result);
    }

    [Fact]
    public void Single_newline_returned_unchanged()
    {
        var input = "\n"u8.ToArray();
        var result = GitSignProgram.NormalizeGitContent(input);

        Assert.Equal(input, result);
    }
}
