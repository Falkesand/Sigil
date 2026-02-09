using Sigil.Policy;

namespace Sigil.Core.Tests.Policy;

public class PolicyLoaderTests
{
    [Fact]
    public void Load_ValidPolicy_Succeeds()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [
            { "require": "timestamp" }
          ]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value.Rules);
    }

    [Fact]
    public void Load_EmptyString_Fails()
    {
        var result = PolicyLoader.Load("");

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Load_InvalidJson_Fails()
    {
        var result = PolicyLoader.Load("{ not json }");

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Load_NullRules_Fails()
    {
        const string json = """{ "version": "1.0" }""";

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("rules", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_EmptyRules_Fails()
    {
        const string json = """{ "version": "1.0", "rules": [] }""";

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
    }

    [Fact]
    public void Load_MissingRequire_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "count": 2 }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        // Missing 'required' property causes JsonException during deserialization
        Assert.Equal(PolicyErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Load_UnknownRequireType_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "bogus-rule" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("bogus-rule", result.ErrorMessage);
    }

    [Fact]
    public void Load_MinSignatures_MissingCount_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "min-signatures" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("count", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_MinSignatures_ZeroCount_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "min-signatures", "count": 0 }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
    }

    [Fact]
    public void Load_Algorithm_MissingAllowed_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "algorithm" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("allowed", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_Algorithm_EmptyAllowed_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "algorithm", "allowed": [] }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
    }

    [Fact]
    public void Load_Label_MissingMatch_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "label" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("match", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_Trusted_MissingBundle_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "trusted" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("bundle", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_UnsupportedVersion_Fails()
    {
        const string json = """
        {
          "version": "2.0",
          "rules": [{ "require": "timestamp" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("2.0", result.ErrorMessage);
    }

    [Fact]
    public void Load_Key_MissingFingerprints_Fails()
    {
        const string json = """
        {
          "version": "1.0",
          "rules": [{ "require": "key" }]
        }
        """;

        var result = PolicyLoader.Load(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(PolicyErrorKind.InvalidPolicy, result.ErrorKind);
        Assert.Contains("fingerprints", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
