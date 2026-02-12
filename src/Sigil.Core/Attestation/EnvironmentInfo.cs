namespace Sigil.Attestation;

public sealed class EnvironmentInfo
{
    public string OsDescription { get; init; } = "";
    public string Architecture { get; init; } = "";
    public int ProcessorCount { get; init; }
    public string RuntimeVersion { get; init; } = "";
    public string FrameworkDescription { get; init; } = "";
    public string MachineName { get; init; } = "";
    public string CollectedAt { get; init; } = "";
}
