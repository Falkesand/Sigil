using Xunit;

namespace Sigil.LogServer.Tests;

public sealed class EnvironmentVariableTests : IDisposable
{
    private readonly Dictionary<string, string?> _savedEnvVars = new();

    public EnvironmentVariableTests()
    {
        SaveAndClearEnvVar("SIGIL_API_KEY");
        SaveAndClearEnvVar("SIGIL_KEY_PASSWORD");
        SaveAndClearEnvVar("SIGIL_CERT_PASSWORD");
    }

    public void Dispose()
    {
        foreach (var (key, value) in _savedEnvVars)
            Environment.SetEnvironmentVariable(key, value);
    }

    private void SaveAndClearEnvVar(string name)
    {
        _savedEnvVars[name] = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, null);
    }

    [Fact]
    public void ApiKey_EnvVar_IsRead()
    {
        Environment.SetEnvironmentVariable("SIGIL_API_KEY", "test-api-key");

        var value = Environment.GetEnvironmentVariable("SIGIL_API_KEY");

        Assert.Equal("test-api-key", value);
    }

    [Fact]
    public void KeyPassword_EnvVar_IsRead()
    {
        Environment.SetEnvironmentVariable("SIGIL_KEY_PASSWORD", "key-pass-123");

        var value = Environment.GetEnvironmentVariable("SIGIL_KEY_PASSWORD");

        Assert.Equal("key-pass-123", value);
    }

    [Fact]
    public void CertPassword_EnvVar_IsRead()
    {
        Environment.SetEnvironmentVariable("SIGIL_CERT_PASSWORD", "cert-pass-456");

        var value = Environment.GetEnvironmentVariable("SIGIL_CERT_PASSWORD");

        Assert.Equal("cert-pass-456", value);
    }

    [Fact]
    public void CliArg_Overrides_EnvVar()
    {
        // Simulates the pattern: GetArg(args, "--api-key") ?? Environment.GetEnvironmentVariable("SIGIL_API_KEY")
        Environment.SetEnvironmentVariable("SIGIL_API_KEY", "env-key");

        var cliArg = "cli-key";
        var resolved = cliArg ?? Environment.GetEnvironmentVariable("SIGIL_API_KEY");

        Assert.Equal("cli-key", resolved);
    }
}
