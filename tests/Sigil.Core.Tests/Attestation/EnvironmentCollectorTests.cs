using System.Text.Json;
using Sigil.Attestation;

namespace Sigil.Core.Tests.Attestation;

[Collection("Environment")]
public class EnvironmentCollectorTests
{
    private static readonly string[] CiVarNames =
        ["GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "CI"];

    private static void WithEnvironmentVariables(Dictionary<string, string?> vars, Action action)
    {
        var original = new Dictionary<string, string?>();
        try
        {
            foreach (var (key, value) in vars)
            {
                original[key] = System.Environment.GetEnvironmentVariable(key);
                System.Environment.SetEnvironmentVariable(key, value);
            }

            action();
        }
        finally
        {
            foreach (var (key, value) in original)
            {
                System.Environment.SetEnvironmentVariable(key, value);
            }
        }
    }

    private static Dictionary<string, string?> ClearAllCiVars()
    {
        var vars = new Dictionary<string, string?>();
        foreach (var name in CiVarNames)
        {
            vars[name] = null;
        }

        return vars;
    }

    [Fact]
    public void Collect_returns_non_null_EnvironmentInfo_with_os_arch_runtime()
    {
        var result = EnvironmentCollector.Collect();

        Assert.NotNull(result.Environment);
        Assert.False(string.IsNullOrEmpty(result.Environment.OsDescription));
        Assert.False(string.IsNullOrEmpty(result.Environment.Architecture));
        Assert.True(result.Environment.ProcessorCount > 0);
        Assert.False(string.IsNullOrEmpty(result.Environment.RuntimeVersion));
        Assert.False(string.IsNullOrEmpty(result.Environment.FrameworkDescription));
        Assert.False(string.IsNullOrEmpty(result.Environment.MachineName));
        Assert.False(string.IsNullOrEmpty(result.Environment.CollectedAt));
    }

    [Fact]
    public void Collect_collectedAt_is_iso8601_format()
    {
        var result = EnvironmentCollector.Collect();

        Assert.True(
            DateTimeOffset.TryParse(result.Environment.CollectedAt, out _),
            "CollectedAt should be parseable as DateTimeOffset");
    }

    [Fact]
    public void Collect_without_CI_env_vars_returns_null_CiEnvironment()
    {
        var vars = ClearAllCiVars();

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.Null(result.Ci);
        });
    }

    [Fact]
    public void Collect_with_GITHUB_ACTIONS_detects_github_actions()
    {
        var vars = ClearAllCiVars();
        vars["GITHUB_ACTIONS"] = "true";
        vars["RUNNER_NAME"] = "test-runner";
        vars["GITHUB_WORKFLOW"] = "CI";
        vars["GITHUB_REPOSITORY"] = "org/repo";
        vars["GITHUB_SHA"] = "abc123def456";
        vars["GITHUB_REF"] = "refs/heads/main";
        vars["GITHUB_JOB"] = "build";
        vars["GITHUB_EVENT_NAME"] = "push";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("github-actions", result.Ci.Provider);
            Assert.Equal("test-runner", result.Ci.RunnerId);
            Assert.Equal("CI", result.Ci.Pipeline);
            Assert.Equal("org/repo", result.Ci.Repository);
            Assert.Equal("abc123def456", result.Ci.CommitSha);
            Assert.Equal("refs/heads/main", result.Ci.Branch);
            Assert.Equal("build", result.Ci.JobName);
            Assert.Equal("push", result.Ci.Trigger);
        });
    }

    [Fact]
    public void Collect_with_GITLAB_CI_detects_gitlab_ci()
    {
        var vars = ClearAllCiVars();
        vars["GITLAB_CI"] = "true";
        vars["CI_RUNNER_ID"] = "42";
        vars["CI_PIPELINE_ID"] = "99";
        vars["CI_PROJECT_PATH"] = "group/project";
        vars["CI_COMMIT_SHA"] = "def456abc789";
        vars["CI_COMMIT_REF_NAME"] = "main";
        vars["CI_JOB_NAME"] = "test";
        vars["CI_PIPELINE_SOURCE"] = "push";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("gitlab-ci", result.Ci.Provider);
            Assert.Equal("42", result.Ci.RunnerId);
            Assert.Equal("99", result.Ci.Pipeline);
            Assert.Equal("group/project", result.Ci.Repository);
            Assert.Equal("def456abc789", result.Ci.CommitSha);
            Assert.Equal("main", result.Ci.Branch);
            Assert.Equal("test", result.Ci.JobName);
            Assert.Equal("push", result.Ci.Trigger);
        });
    }

    [Fact]
    public void Collect_with_TF_BUILD_detects_azure_pipelines()
    {
        var vars = ClearAllCiVars();
        vars["TF_BUILD"] = "True";
        vars["AGENT_NAME"] = "agent-1";
        vars["BUILD_DEFINITIONNAME"] = "MyBuild";
        vars["BUILD_REPOSITORY_URI"] = "https://dev.azure.com/org/project";
        vars["BUILD_SOURCEVERSION"] = "ghi789abc012";
        vars["BUILD_SOURCEBRANCH"] = "refs/heads/main";
        vars["AGENT_JOBNAME"] = "Job1";
        vars["BUILD_REASON"] = "manual";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("azure-pipelines", result.Ci.Provider);
            Assert.Equal("agent-1", result.Ci.RunnerId);
            Assert.Equal("MyBuild", result.Ci.Pipeline);
            Assert.Equal("https://dev.azure.com/org/project", result.Ci.Repository);
            Assert.Equal("ghi789abc012", result.Ci.CommitSha);
            Assert.Equal("refs/heads/main", result.Ci.Branch);
            Assert.Equal("Job1", result.Ci.JobName);
            Assert.Equal("manual", result.Ci.Trigger);
        });
    }

    [Fact]
    public void Collect_with_CI_env_var_detects_generic()
    {
        var vars = ClearAllCiVars();
        vars["CI"] = "true";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("generic", result.Ci.Provider);
        });
    }

    [Fact]
    public void Collect_github_actions_takes_priority_over_generic_CI()
    {
        var vars = ClearAllCiVars();
        vars["GITHUB_ACTIONS"] = "true";
        vars["CI"] = "true";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("github-actions", result.Ci.Provider);
        });
    }

    [Fact]
    public void Collect_gitlab_takes_priority_over_generic_CI()
    {
        var vars = ClearAllCiVars();
        vars["GITLAB_CI"] = "true";
        vars["CI"] = "true";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("gitlab-ci", result.Ci.Provider);
        });
    }

    [Fact]
    public void Collect_azure_takes_priority_over_generic_CI()
    {
        var vars = ClearAllCiVars();
        vars["TF_BUILD"] = "True";
        vars["CI"] = "true";

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect();

            Assert.NotNull(result.Ci);
            Assert.Equal("azure-pipelines", result.Ci.Provider);
        });
    }

    [Fact]
    public void Collect_without_include_patterns_returns_null_custom_variables()
    {
        var result = EnvironmentCollector.Collect();

        Assert.Null(result.CustomVariables);
    }

    [Fact]
    public void Collect_with_empty_include_patterns_returns_null_custom_variables()
    {
        var result = EnvironmentCollector.Collect([]);

        Assert.Null(result.CustomVariables);
    }

    [Fact]
    public void Collect_with_include_var_captures_matching_env_vars()
    {
        var vars = new Dictionary<string, string?>
        {
            ["SIGIL_TEST_VAR_ALPHA"] = "hello",
            ["SIGIL_TEST_VAR_BETA"] = "world",
            ["SIGIL_TEST_OTHER_GAMMA"] = "skip",
        };

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect(["SIGIL_TEST_VAR_*"]);

            Assert.NotNull(result.CustomVariables);
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_TEST_VAR_ALPHA"));
            Assert.Equal("hello", result.CustomVariables["SIGIL_TEST_VAR_ALPHA"]);
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_TEST_VAR_BETA"));
            Assert.Equal("world", result.CustomVariables["SIGIL_TEST_VAR_BETA"]);
            Assert.False(result.CustomVariables.ContainsKey("SIGIL_TEST_OTHER_GAMMA"));
        });
    }

    [Fact]
    public void Collect_with_include_var_no_matches_returns_null_custom_variables()
    {
        var result = EnvironmentCollector.Collect(["ZZZZZ_NONEXISTENT_PATTERN_*"]);

        Assert.Null(result.CustomVariables);
    }

    [Fact]
    public void Collect_with_multiple_include_patterns_matches_all()
    {
        var vars = new Dictionary<string, string?>
        {
            ["SIGIL_MPAT_FOO"] = "a",
            ["SIGIL_MPAT_BAR"] = "b",
            ["SIGIL_XPAT_BAZ"] = "c",
        };

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect(["SIGIL_MPAT_*", "SIGIL_XPAT_*"]);

            Assert.NotNull(result.CustomVariables);
            Assert.Equal(3, result.CustomVariables.Count);
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_MPAT_FOO"));
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_MPAT_BAR"));
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_XPAT_BAZ"));
        });
    }

    [Theory]
    [InlineData("MY_TOKEN_VAR")]
    [InlineData("MY_SECRET_VAR")]
    [InlineData("MY_PASSWORD_VAR")]
    [InlineData("MY_KEY_VAR")]
    [InlineData("MY_CREDENTIAL_VAR")]
    [InlineData("MY_AUTH_VAR")]
    [InlineData("MY_PRIVATE_VAR")]
    [InlineData("MY_SIGNING_VAR")]
    [InlineData("MY_BEARER_VAR")]
    [InlineData("MY_CONNECTION_VAR")]
    [InlineData("MY_CONNSTR_VAR")]
    [InlineData("MY_PASSPHRASE_VAR")]
    public void Collect_blocklist_filters_sensitive_variable(string sensitiveVarName)
    {
        var vars = new Dictionary<string, string?>
        {
            [sensitiveVarName] = "secret_value",
        };

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect(["MY_*"]);

            if (result.CustomVariables is not null)
            {
                Assert.False(
                    result.CustomVariables.ContainsKey(sensitiveVarName),
                    $"Variable '{sensitiveVarName}' should be blocklisted");
            }
        });
    }

    [Fact]
    public void Collect_blocklist_allows_safe_variables()
    {
        var vars = new Dictionary<string, string?>
        {
            ["SIGIL_SAFE_VALUE"] = "safe_value",
        };

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect(["SIGIL_SAFE_*"]);

            Assert.NotNull(result.CustomVariables);
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_SAFE_VALUE"));
            Assert.Equal("safe_value", result.CustomVariables["SIGIL_SAFE_VALUE"]);
        });
    }

    [Fact]
    public void Collect_include_pattern_is_case_insensitive()
    {
        var vars = new Dictionary<string, string?>
        {
            ["sigil_ci_test_lower"] = "lower_value",
        };

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect(["SIGIL_CI_TEST_*"]);

            Assert.NotNull(result.CustomVariables);
            Assert.True(result.CustomVariables.ContainsKey("sigil_ci_test_lower"));
        });
    }

    [Fact]
    public void Collect_question_mark_glob_matches_single_char()
    {
        var vars = new Dictionary<string, string?>
        {
            ["SIGIL_QMARK_A"] = "val_a",
            ["SIGIL_QMARK_B"] = "val_b",
            ["SIGIL_QMARK_AB"] = "val_ab",
        };

        WithEnvironmentVariables(vars, () =>
        {
            var result = EnvironmentCollector.Collect(["SIGIL_QMARK_?"]);

            Assert.NotNull(result.CustomVariables);
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_QMARK_A"));
            Assert.True(result.CustomVariables.ContainsKey("SIGIL_QMARK_B"));
            Assert.False(result.CustomVariables.ContainsKey("SIGIL_QMARK_AB"));
        });
    }

    [Fact]
    public void ToJsonElement_produces_valid_JSON_with_environment_field()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo
            {
                OsDescription = "TestOS 10.0",
                Architecture = "X64",
                ProcessorCount = 4,
                RuntimeVersion = "10.0.0",
                FrameworkDescription = ".NET 10.0.0",
                MachineName = "test-machine",
                CollectedAt = "2025-01-01T00:00:00+00:00",
            },
        };

        var element = fp.ToJsonElement();

        Assert.Equal(JsonValueKind.Object, element.ValueKind);
        Assert.True(element.TryGetProperty("environment", out var env));
        Assert.Equal("TestOS 10.0", env.GetProperty("osDescription").GetString());
        Assert.Equal("X64", env.GetProperty("architecture").GetString());
        Assert.Equal(4, env.GetProperty("processorCount").GetInt32());
        Assert.Equal("10.0.0", env.GetProperty("runtimeVersion").GetString());
        Assert.Equal(".NET 10.0.0", env.GetProperty("frameworkDescription").GetString());
        Assert.Equal("test-machine", env.GetProperty("machineName").GetString());
        Assert.Equal("2025-01-01T00:00:00+00:00", env.GetProperty("collectedAt").GetString());
    }

    [Fact]
    public void ToJsonElement_uses_camelCase_property_names()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo
            {
                OsDescription = "TestOS",
                ProcessorCount = 2,
            },
        };

        var element = fp.ToJsonElement();
        var env = element.GetProperty("environment");

        Assert.True(env.TryGetProperty("osDescription", out _));
        Assert.True(env.TryGetProperty("processorCount", out _));
        Assert.True(env.TryGetProperty("runtimeVersion", out _));
        Assert.False(env.TryGetProperty("OsDescription", out _));
        Assert.False(env.TryGetProperty("ProcessorCount", out _));
    }

    [Fact]
    public void ToJsonElement_includes_ci_field_when_present()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo { OsDescription = "TestOS" },
            Ci = new CiEnvironment
            {
                Provider = "github-actions",
                RunnerId = "runner-1",
                Pipeline = "CI",
                Repository = "org/repo",
                CommitSha = "abc123",
                Branch = "refs/heads/main",
                JobName = "build",
                Trigger = "push",
            },
        };

        var element = fp.ToJsonElement();

        Assert.True(element.TryGetProperty("ci", out var ci));
        Assert.Equal("github-actions", ci.GetProperty("provider").GetString());
        Assert.Equal("runner-1", ci.GetProperty("runnerId").GetString());
        Assert.Equal("CI", ci.GetProperty("pipeline").GetString());
        Assert.Equal("org/repo", ci.GetProperty("repository").GetString());
        Assert.Equal("abc123", ci.GetProperty("commitSha").GetString());
        Assert.Equal("refs/heads/main", ci.GetProperty("branch").GetString());
        Assert.Equal("build", ci.GetProperty("jobName").GetString());
        Assert.Equal("push", ci.GetProperty("trigger").GetString());
    }

    [Fact]
    public void ToJsonElement_excludes_ci_field_when_null()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo { OsDescription = "TestOS" },
        };

        var element = fp.ToJsonElement();

        Assert.False(element.TryGetProperty("ci", out _));
    }

    [Fact]
    public void ToJsonElement_includes_customVariables_when_present()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo { OsDescription = "TestOS" },
            CustomVariables = new Dictionary<string, string>
            {
                ["FOO"] = "bar",
                ["BAZ"] = "qux",
            },
        };

        var element = fp.ToJsonElement();

        Assert.True(element.TryGetProperty("customVariables", out var vars));
        Assert.Equal("bar", vars.GetProperty("FOO").GetString());
        Assert.Equal("qux", vars.GetProperty("BAZ").GetString());
    }

    [Fact]
    public void ToJsonElement_excludes_customVariables_when_null()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo { OsDescription = "TestOS" },
        };

        var element = fp.ToJsonElement();

        Assert.False(element.TryGetProperty("customVariables", out _));
    }

    [Fact]
    public void ToJsonElement_excludes_null_ci_properties()
    {
        var fp = new EnvironmentFingerprint
        {
            Environment = new EnvironmentInfo { OsDescription = "TestOS" },
            Ci = new CiEnvironment { Provider = "generic" },
        };

        var element = fp.ToJsonElement();
        var ci = element.GetProperty("ci");

        Assert.Equal("generic", ci.GetProperty("provider").GetString());
        Assert.False(ci.TryGetProperty("runnerId", out _));
        Assert.False(ci.TryGetProperty("pipeline", out _));
        Assert.False(ci.TryGetProperty("repository", out _));
        Assert.False(ci.TryGetProperty("commitSha", out _));
        Assert.False(ci.TryGetProperty("branch", out _));
        Assert.False(ci.TryGetProperty("jobName", out _));
        Assert.False(ci.TryGetProperty("trigger", out _));
    }

    [Fact]
    public void Collect_returns_fingerprint_that_roundtrips_through_json()
    {
        var vars = ClearAllCiVars();

        WithEnvironmentVariables(vars, () =>
        {
            var fingerprint = EnvironmentCollector.Collect();
            var element = fingerprint.ToJsonElement();
            var json = element.GetRawText();

            using var doc = JsonDocument.Parse(json);
            Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
            Assert.True(doc.RootElement.TryGetProperty("environment", out _));
        });
    }
}
