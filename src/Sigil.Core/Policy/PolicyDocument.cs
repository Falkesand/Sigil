namespace Sigil.Policy;

public sealed class PolicyDocument
{
    public string Version { get; set; } = "1.0";
    public List<PolicyRule> Rules { get; set; } = [];
}
