using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Sigil.Attestation;

public static class EnvironmentCollector
{
    private static readonly string[] Blocklist =
        ["AUTH", "BEARER", "CONNECTION", "CONNSTR", "CREDENTIAL", "KEY", "PASSPHRASE", "PASSWORD", "PRIVATE", "SECRET", "SIGNING", "TOKEN"];

    public static EnvironmentFingerprint Collect(IReadOnlyList<string>? includeVarPatterns = null)
    {
        var environment = new EnvironmentInfo
        {
            OsDescription = RuntimeInformation.OSDescription,
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            ProcessorCount = System.Environment.ProcessorCount,
            RuntimeVersion = System.Environment.Version.ToString(),
            FrameworkDescription = RuntimeInformation.FrameworkDescription,
            MachineName = System.Environment.MachineName,
            CollectedAt = DateTimeOffset.UtcNow.ToString("O"),
        };

        var ci = DetectCi();
        var customVars = CollectCustomVariables(includeVarPatterns);

        return new EnvironmentFingerprint
        {
            Environment = environment,
            Ci = ci,
            CustomVariables = customVars,
        };
    }

    private static CiEnvironment? DetectCi()
    {
        if (System.Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true")
        {
            return new CiEnvironment
            {
                Provider = "github-actions",
                RunnerId = System.Environment.GetEnvironmentVariable("RUNNER_NAME"),
                Pipeline = System.Environment.GetEnvironmentVariable("GITHUB_WORKFLOW"),
                Repository = System.Environment.GetEnvironmentVariable("GITHUB_REPOSITORY"),
                CommitSha = System.Environment.GetEnvironmentVariable("GITHUB_SHA"),
                Branch = System.Environment.GetEnvironmentVariable("GITHUB_REF"),
                JobName = System.Environment.GetEnvironmentVariable("GITHUB_JOB"),
                Trigger = System.Environment.GetEnvironmentVariable("GITHUB_EVENT_NAME"),
            };
        }

        if (System.Environment.GetEnvironmentVariable("GITLAB_CI") == "true")
        {
            return new CiEnvironment
            {
                Provider = "gitlab-ci",
                RunnerId = System.Environment.GetEnvironmentVariable("CI_RUNNER_ID"),
                Pipeline = System.Environment.GetEnvironmentVariable("CI_PIPELINE_ID"),
                Repository = System.Environment.GetEnvironmentVariable("CI_PROJECT_PATH"),
                CommitSha = System.Environment.GetEnvironmentVariable("CI_COMMIT_SHA"),
                Branch = System.Environment.GetEnvironmentVariable("CI_COMMIT_REF_NAME"),
                JobName = System.Environment.GetEnvironmentVariable("CI_JOB_NAME"),
                Trigger = System.Environment.GetEnvironmentVariable("CI_PIPELINE_SOURCE"),
            };
        }

        if (System.Environment.GetEnvironmentVariable("TF_BUILD") == "True")
        {
            return new CiEnvironment
            {
                Provider = "azure-pipelines",
                RunnerId = System.Environment.GetEnvironmentVariable("AGENT_NAME"),
                Pipeline = System.Environment.GetEnvironmentVariable("BUILD_DEFINITIONNAME"),
                Repository = System.Environment.GetEnvironmentVariable("BUILD_REPOSITORY_URI"),
                CommitSha = System.Environment.GetEnvironmentVariable("BUILD_SOURCEVERSION"),
                Branch = System.Environment.GetEnvironmentVariable("BUILD_SOURCEBRANCH"),
                JobName = System.Environment.GetEnvironmentVariable("AGENT_JOBNAME"),
                Trigger = System.Environment.GetEnvironmentVariable("BUILD_REASON"),
            };
        }

        if (System.Environment.GetEnvironmentVariable("CI") is not null)
        {
            return new CiEnvironment { Provider = "generic" };
        }

        return null;
    }

    private static Dictionary<string, string>? CollectCustomVariables(IReadOnlyList<string>? patterns)
    {
        if (patterns is null || patterns.Count == 0)
            return null;

        var regexes = patterns.Select(GlobToRegex).ToList();
        var result = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in System.Environment.GetEnvironmentVariables())
        {
            if (entry is not System.Collections.DictionaryEntry de)
                continue;

            var name = de.Key?.ToString();
            var value = de.Value?.ToString();
            if (string.IsNullOrEmpty(name) || value is null)
                continue;

            if (IsBlocklisted(name))
                continue;

            if (regexes.Any(r => r.IsMatch(name)))
                result[name] = value;
        }

        return result.Count > 0 ? new Dictionary<string, string>(result) : null;
    }

    private static bool IsBlocklisted(string name)
    {
        var upper = name.ToUpperInvariant();
        return Blocklist.Any(b => upper.Contains(b, StringComparison.Ordinal));
    }

    private static Regex GlobToRegex(string pattern)
    {
        var escaped = Regex.Escape(pattern);
        var regexPattern = escaped
            .Replace(@"\*", ".*")
            .Replace(@"\?", ".");
        return new Regex("^" + regexPattern + "$", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    }
}
