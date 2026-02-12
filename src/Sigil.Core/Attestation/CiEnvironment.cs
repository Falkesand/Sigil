namespace Sigil.Attestation;

public sealed class CiEnvironment
{
    public string Provider { get; init; } = "";
    public string? RunnerId { get; init; }
    public string? Pipeline { get; init; }
    public string? Repository { get; init; }
    public string? CommitSha { get; init; }
    public string? Branch { get; init; }
    public string? JobName { get; init; }
    public string? Trigger { get; init; }
}
