using Microsoft.AspNetCore.Http;
using Xunit;

namespace Sigil.LogServer.Tests;

public sealed class ApiKeyMiddlewareTests
{
    private const string ValidApiKey = "test-api-key-123";

    [Fact]
    public async Task GetRequest_WithoutApiKey_PassesThrough()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };
        var middleware = new ApiKeyMiddleware(next, ValidApiKey);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.True(nextCalled);
        Assert.NotEqual(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task PostRequest_WithoutApiKeyHeader_Returns401()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Response.Body = new MemoryStream();
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };
        var middleware = new ApiKeyMiddleware(next, ValidApiKey);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task PostRequest_WithWrongApiKey_Returns401()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Headers["X-Api-Key"] = "wrong-api-key";
        context.Response.Body = new MemoryStream();
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };
        var middleware = new ApiKeyMiddleware(next, ValidApiKey);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task PostRequest_WithCorrectApiKey_PassesThrough()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Headers["X-Api-Key"] = ValidApiKey;
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };
        var middleware = new ApiKeyMiddleware(next, ValidApiKey);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.True(nextCalled);
        Assert.NotEqual(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task GetRequest_WithWrongApiKey_StillPassesThrough()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Headers["X-Api-Key"] = "wrong-api-key";
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };
        var middleware = new ApiKeyMiddleware(next, ValidApiKey);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.True(nextCalled);
        Assert.NotEqual(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task ResponseBody_On401_ContainsInvalidOrMissingApiKeyMessage()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;
        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new ApiKeyMiddleware(next, ValidApiKey);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(memoryStream);
        var responseBody = await reader.ReadToEndAsync();
        Assert.Contains("Invalid or missing API key", responseBody);
    }
}
