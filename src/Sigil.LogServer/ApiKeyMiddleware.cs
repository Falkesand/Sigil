using System.Security.Cryptography;
using System.Text;

namespace Sigil.LogServer;

public sealed class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly byte[] _apiKeyHash;

    public ApiKeyMiddleware(RequestDelegate next, string apiKey)
    {
        _next = next;
        _apiKeyHash = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only require API key for POST requests
        if (context.Request.Method == HttpMethod.Post.Method)
        {
            if (!context.Request.Headers.TryGetValue("X-Api-Key", out var providedKey) ||
                !VerifyApiKey(providedKey.ToString()))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"Invalid or missing API key.\"}");
                return;
            }
        }

        await _next(context);
    }

    private bool VerifyApiKey(string providedKey)
    {
        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(providedKey));
        return CryptographicOperations.FixedTimeEquals(providedHash, _apiKeyHash);
    }
}
