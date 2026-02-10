using System.Text.Json;

namespace Sigil.Policy;

public static class PolicyLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly HashSet<string> ValidRuleTypes = new(StringComparer.Ordinal)
    {
        "min-signatures", "timestamp", "sbom-metadata",
        "algorithm", "label", "trusted", "key", "logged"
    };

    public static PolicyResult<PolicyDocument> Load(string json)
    {
        PolicyDocument? doc;
        try
        {
            doc = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            return PolicyResult<PolicyDocument>.Fail(
                PolicyErrorKind.DeserializationFailed,
                $"Failed to parse policy JSON: {ex.Message}");
        }

        if (doc is null)
        {
            return PolicyResult<PolicyDocument>.Fail(
                PolicyErrorKind.DeserializationFailed,
                "Policy document deserialized to null.");
        }

        return Validate(doc);
    }

    private static PolicyResult<PolicyDocument> Validate(PolicyDocument doc)
    {
        if (doc.Version != "1.0")
        {
            return PolicyResult<PolicyDocument>.Fail(
                PolicyErrorKind.InvalidPolicy,
                $"Unsupported policy version: '{doc.Version}'. Only '1.0' is supported.");
        }

        if (doc.Rules is not { Count: > 0 })
        {
            return PolicyResult<PolicyDocument>.Fail(
                PolicyErrorKind.InvalidPolicy,
                "Policy must contain at least one rule in the rules array.");
        }

        for (var i = 0; i < doc.Rules.Count; i++)
        {
            var rule = doc.Rules[i];

            if (string.IsNullOrWhiteSpace(rule.Require))
            {
                return PolicyResult<PolicyDocument>.Fail(
                    PolicyErrorKind.InvalidPolicy,
                    $"Rule at index {i} is missing the required 'require' field.");
            }

            if (!ValidRuleTypes.Contains(rule.Require))
            {
                return PolicyResult<PolicyDocument>.Fail(
                    PolicyErrorKind.InvalidPolicy,
                    $"Unknown rule type '{rule.Require}' at index {i}.");
            }

            var validation = ValidateRule(rule, i);
            if (validation is not null)
            {
                return PolicyResult<PolicyDocument>.Fail(PolicyErrorKind.InvalidPolicy, validation);
            }
        }

        return PolicyResult<PolicyDocument>.Ok(doc);
    }

    private static string? ValidateRule(PolicyRule rule, int index)
    {
        return rule.Require switch
        {
            "min-signatures" when rule.Count is null or <= 0 =>
                $"Rule 'min-signatures' at index {index} requires 'count' >= 1.",
            "algorithm" when rule.Allowed is not { Count: > 0 } =>
                $"Rule 'algorithm' at index {index} requires a non-empty 'allowed' list.",
            "label" when string.IsNullOrWhiteSpace(rule.Match) =>
                $"Rule 'label' at index {index} requires a non-empty 'match' pattern.",
            "trusted" when string.IsNullOrWhiteSpace(rule.Bundle) =>
                $"Rule 'trusted' at index {index} requires a non-empty 'bundle' path.",
            "key" when rule.Fingerprints is not { Count: > 0 } =>
                $"Rule 'key' at index {index} requires a non-empty 'fingerprints' list.",
            _ => null
        };
    }
}
