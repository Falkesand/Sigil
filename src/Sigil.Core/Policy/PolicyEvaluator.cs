namespace Sigil.Policy;

public static class PolicyEvaluator
{
    public static PolicyEvaluationResult Evaluate(PolicyDocument policy, PolicyContext context)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(context);

        var results = new List<RuleResult>(policy.Rules.Count);

        foreach (var rule in policy.Rules)
        {
            results.Add(EvaluateRule(rule, context));
        }

        return new PolicyEvaluationResult { Results = results };
    }

    private static RuleResult EvaluateRule(PolicyRule rule, PolicyContext context)
    {
        return rule.Require switch
        {
            "min-signatures" => RuleEvaluator.EvaluateMinSignatures(rule, context),
            "timestamp" => RuleEvaluator.EvaluateTimestamp(rule, context),
            "sbom-metadata" => RuleEvaluator.EvaluateSbomMetadata(rule, context),
            "algorithm" => RuleEvaluator.EvaluateAlgorithm(rule, context),
            "label" => RuleEvaluator.EvaluateLabel(rule, context),
            "trusted" => RuleEvaluator.EvaluateTrusted(rule, context),
            "key" => RuleEvaluator.EvaluateKey(rule, context),
            "logged" => RuleEvaluator.EvaluateLogged(rule, context),
            _ => new RuleResult
            {
                RuleName = rule.Require,
                Passed = false,
                Reason = $"Unknown rule type: {rule.Require}"
            }
        };
    }
}
