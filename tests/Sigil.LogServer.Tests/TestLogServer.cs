using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Sigil.LogServer;
using Sigil.LogServer.Storage;

namespace Sigil.LogServer.Tests;

/// <summary>
/// Creates an in-process test server with file-backed SQLite and a generated checkpoint signer.
/// Uses HTTP (no TLS) for test simplicity.
/// </summary>
public sealed class TestLogServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly SqliteLogStore _store;
    private readonly CheckpointSigner _signer;
    private readonly string _dbPath;

    public HttpClient Client { get; }
    public CheckpointSigner Signer => _signer;
    public string ApiKey { get; }

    private TestLogServer(WebApplication app, SqliteLogStore store, CheckpointSigner signer, HttpClient client, string apiKey, string dbPath)
    {
        _app = app;
        _store = store;
        _signer = signer;
        Client = client;
        ApiKey = apiKey;
        _dbPath = dbPath;
    }

    public static async Task<TestLogServer> CreateAsync(string? apiKey = null)
    {
        apiKey ??= "test-api-key-" + Guid.NewGuid().ToString("N")[..8];
        var dbPath = Path.Combine(Path.GetTempPath(), $"sigil-logserver-test-{Guid.NewGuid():N}.db");

        var store = new SqliteLogStore(dbPath);
        await store.InitializeAsync();

        var signer = CheckpointSigner.Generate();
        var logService = new LogService(store, signer);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton<ILogStore>(store);
        builder.Services.AddSingleton(signer);
        builder.Services.AddSingleton(logService);

        var app = builder.Build();
        app.UseMiddleware<ApiKeyMiddleware>(apiKey);
        EndpointMapper.Map(app, logService, store, signer);

        await app.StartAsync();

        var address = app.Urls.First();
        var client = new HttpClient { BaseAddress = new Uri(address) };
        client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);

        return new TestLogServer(app, store, signer, client, apiKey, dbPath);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        await _store.DisposeAsync();
        _signer.Dispose();

        try { File.Delete(_dbPath); } catch { /* best-effort cleanup */ }
    }
}
