using Sigil.LogServer.Storage;
using Xunit;

namespace Sigil.LogServer.Tests.Storage;

public sealed class PostgresLogStoreTests
{
    [Fact]
    public async Task Constructor_AcceptsConnectionString()
    {
        await using var store = new PostgresLogStore("Host=test;Database=test;");
        Assert.NotNull(store);
    }

    [Fact]
    public async Task ImplementsILogStore()
    {
        await using var store = new PostgresLogStore("Host=test;Database=test;");
        Assert.IsAssignableFrom<ILogStore>(store);
    }

    [Fact]
    public async Task ImplementsIAsyncDisposable()
    {
        await using var store = new PostgresLogStore("Host=test;Database=test;");
        Assert.IsAssignableFrom<IAsyncDisposable>(store);
    }
}
