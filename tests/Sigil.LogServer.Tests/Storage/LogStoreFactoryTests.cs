using Sigil.LogServer.Storage;
using Xunit;

namespace Sigil.LogServer.Tests.Storage;

public sealed class LogStoreFactoryTests
{
    [Fact]
    public async Task Create_Sqlite_ReturnsSqliteLogStore()
    {
        await using var store = LogStoreFactory.Create("sqlite", "test.db", null);
        Assert.IsType<SqliteLogStore>(store);
    }

    [Fact]
    public async Task Create_SqliteDefault_WhenDbPathNull_UsesDefault()
    {
        await using var store = LogStoreFactory.Create("sqlite", null, null);
        Assert.IsType<SqliteLogStore>(store);
    }

    [Fact]
    public async Task Create_SqlServer_ReturnsSqlServerLogStore()
    {
        await using var store = LogStoreFactory.Create("sqlserver", null, "Server=test;Database=test;");
        Assert.IsType<SqlServerLogStore>(store);
    }

    [Fact]
    public void Create_SqlServer_WithoutConnectionString_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => LogStoreFactory.Create("sqlserver", null, null));
        Assert.Equal("connectionString", ex.ParamName);
        Assert.Contains("Connection string is required for SQL Server provider.", ex.Message);
    }

    [Fact]
    public async Task Create_Postgres_ReturnsPostgresLogStore()
    {
        await using var store = LogStoreFactory.Create("postgres", null, "Host=test;Database=test;");
        Assert.IsType<PostgresLogStore>(store);
    }

    [Fact]
    public void Create_Postgres_WithoutConnectionString_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => LogStoreFactory.Create("postgres", null, null));
        Assert.Equal("connectionString", ex.ParamName);
        Assert.Contains("Connection string is required for PostgreSQL provider.", ex.Message);
    }

    [Fact]
    public void Create_UnknownProvider_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => LogStoreFactory.Create("unknown", null, null));
        Assert.Equal("provider", ex.ParamName);
        Assert.Contains("Unsupported log store provider: unknown", ex.Message);
    }

    [Fact]
    public async Task Create_CaseInsensitive()
    {
        await using var store = LogStoreFactory.Create("SQLite", "test.db", null);
        Assert.IsType<SqliteLogStore>(store);
    }
}
