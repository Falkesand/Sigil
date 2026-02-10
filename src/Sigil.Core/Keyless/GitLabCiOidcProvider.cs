namespace Sigil.Keyless;

public sealed class GitLabCiOidcProvider : IOidcTokenProvider
{
    private const string GitLabCiEnvVar = "GITLAB_CI";
    private const string DefaultTokenEnvVar = "SIGIL_ID_TOKEN";

    private readonly string _token;

    public string ProviderName => "GitLab CI";

    public GitLabCiOidcProvider()
        : this(Environment.GetEnvironmentVariable(DefaultTokenEnvVar) ?? "")
    {
    }

    public GitLabCiOidcProvider(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        _token = token;
    }

    public Task<KeylessResult<string>> AcquireTokenAsync(
        string audience, CancellationToken ct = default)
    {
        // GitLab tokens have fixed audience from .gitlab-ci.yml — audience param ignored
        return Task.FromResult(KeylessResult<string>.Ok(_token));
    }

    public static bool IsAvailable()
    {
        return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(GitLabCiEnvVar)) &&
               !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(DefaultTokenEnvVar));
    }
}
