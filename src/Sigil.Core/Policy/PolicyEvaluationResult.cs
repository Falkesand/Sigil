namespace Sigil.Policy;

public sealed class PolicyEvaluationResult
{
    public required IReadOnlyList<RuleResult> Results { get; init; }

    public bool AllPassed => Results.All(r => r.Passed);
    public bool AnyFailed => Results.Any(r => !r.Passed);
}
