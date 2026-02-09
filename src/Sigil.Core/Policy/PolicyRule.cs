namespace Sigil.Policy;

public sealed class PolicyRule
{
    public required string Require { get; set; }
    public int? Count { get; set; }
    public List<string>? Allowed { get; set; }
    public string? Match { get; set; }
    public string? Bundle { get; set; }
    public string? Authority { get; set; }
    public List<string>? Fingerprints { get; set; }
}
