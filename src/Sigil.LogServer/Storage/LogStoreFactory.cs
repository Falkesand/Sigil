namespace Sigil.LogServer.Storage;

public static class LogStoreFactory
{
    public static ILogStore Create(string provider, string? dbPath, string? connectionString)
    {
        return provider.ToLowerInvariant() switch
        {
            "sqlite" => new SqliteLogStore(dbPath ?? "sigil-log.db"),
            "sqlserver" => connectionString is not null
                ? new SqlServerLogStore(connectionString)
                : throw new ArgumentException("Connection string is required for SQL Server provider.", nameof(connectionString)),
            "postgres" => connectionString is not null
                ? new PostgresLogStore(connectionString)
                : throw new ArgumentException("Connection string is required for PostgreSQL provider.", nameof(connectionString)),
            _ => throw new ArgumentException($"Unsupported log store provider: {provider}", nameof(provider))
        };
    }
}
