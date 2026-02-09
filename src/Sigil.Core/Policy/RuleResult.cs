namespace Sigil.Policy;

public sealed class RuleResult
{
    public required string RuleName { get; init; }
    public required bool Passed { get; init; }
    public string? Reason { get; init; }
}
