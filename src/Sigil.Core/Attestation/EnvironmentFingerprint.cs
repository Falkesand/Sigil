using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Attestation;

public sealed class EnvironmentFingerprint
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public EnvironmentInfo Environment { get; init; } = new();
    public CiEnvironment? Ci { get; init; }
    public Dictionary<string, string>? CustomVariables { get; init; }

    public JsonElement ToJsonElement()
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(this, SerializerOptions);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }
}
