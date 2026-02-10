using Sigil.LogServer;
using Sigil.LogServer.Storage;

var builder = WebApplication.CreateSlimBuilder(args);

// Parse CLI arguments
var dbPath = GetArg(args, "--db");
var dbProvider = GetArg(args, "--db-provider") ?? "sqlite";
var connectionString = GetArg(args, "--connection-string");
var apiKey = GetArg(args, "--api-key");
var keyPath = GetArg(args, "--key");
var keyPfxPath = GetArg(args, "--key-pfx");
var keyPassword = GetArg(args, "--key-password");
var useDev = args.Contains("--dev-cert");
var certPath = GetArg(args, "--cert");
var certKeyPath = GetArg(args, "--cert-key");
var certPfxPath = GetArg(args, "--cert-pfx");
var certPassword = GetArg(args, "--cert-password");
var mtlsCaPath = GetArg(args, "--mtls-ca");
var listenUrl = GetArg(args, "--listen") ?? "https://localhost:5001";

// Validate mutual exclusivity
if (keyPath is not null && keyPfxPath is not null)
{
    Console.Error.WriteLine("Error: Cannot use both --key and --key-pfx. Choose one.");
    return 1;
}

if (certPath is not null && certPfxPath is not null)
{
    Console.Error.WriteLine("Error: Cannot use both --cert and --cert-pfx. Choose one.");
    return 1;
}

if (keyPassword is not null && keyPfxPath is null)
{
    Console.Error.WriteLine("Error: --key-password requires --key-pfx.");
    return 1;
}

if (certPassword is not null && certPfxPath is null)
{
    Console.Error.WriteLine("Error: --cert-password requires --cert-pfx.");
    return 1;
}

// Validate TLS configuration
if (!useDev && certPath is null && certPfxPath is null)
{
    Console.Error.WriteLine("Error: HTTPS is required. Provide --cert/--cert-key, --cert-pfx, or use --dev-cert for development.");
    return 1;
}

if (apiKey is null)
{
    Console.Error.WriteLine("Error: --api-key is required.");
    return 1;
}

// Configure Kestrel
builder.WebHost.UseKestrelHttpsConfiguration();
builder.WebHost.UseUrls(listenUrl);
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = 1_048_576; // 1 MB max request body
    if (certPfxPath is not null)
    {
        kestrel.ConfigureHttpsDefaults(https =>
        {
            var pfxBytes = File.ReadAllBytes(certPfxPath);
            try
            {
                https.ServerCertificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(
                    pfxBytes, certPassword,
                    System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.EphemeralKeySet);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(pfxBytes);
            }

            if (mtlsCaPath is not null)
            {
                var caCert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(mtlsCaPath);
                https.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = (cert, chain, errors) =>
                {
                    if (chain is null) return false;
                    chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(caCert);
                    return chain.Build(new System.Security.Cryptography.X509Certificates.X509Certificate2(cert));
                };
            }
        });
    }
    else if (certPath is not null && certKeyPath is not null)
    {
        kestrel.ConfigureHttpsDefaults(https =>
        {
            https.ServerCertificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(certPath, certKeyPath);

            if (mtlsCaPath is not null)
            {
                var caCert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(mtlsCaPath);
                https.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = (cert, chain, errors) =>
                {
                    if (chain is null) return false;
                    chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(caCert);
                    return chain.Build(new System.Security.Cryptography.X509Certificates.X509Certificate2(cert));
                };
            }
        });
    }
});

// Initialize storage
ILogStore store;
try
{
    store = LogStoreFactory.Create(dbProvider, dbPath, connectionString);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}
await store.InitializeAsync();

ICheckpointSigner signer;
if (keyPath is not null)
    signer = CheckpointSigner.FromPem(keyPath);
else if (keyPfxPath is not null)
    signer = CheckpointSigner.FromPfx(keyPfxPath, keyPassword);
else
    signer = CheckpointSigner.Generate();

var logService = new LogService(store, signer);

builder.Services.AddSingleton(store);
builder.Services.AddSingleton<ICheckpointSigner>(signer);
builder.Services.AddSingleton(logService);

var app = builder.Build();

// HTTPS redirection + HSTS as defense-in-depth
app.UseHsts();
app.UseHttpsRedirection();

// API key middleware
app.UseMiddleware<ApiKeyMiddleware>(apiKey);

// Map all API endpoints
EndpointMapper.Map(app, logService, store, signer);

await app.RunAsync();
return 0;

static string? GetArg(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

// Make Program accessible for WebApplicationFactory in tests
public partial class Program { }
