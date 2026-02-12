using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Anomaly;

public static class BaselineSerializer
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private static readonly JsonSerializerOptions DeserializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private const string SupportedVersion = "1.0";
    private const string SupportedKind = "anomaly-baseline";

    public static string Serialize(BaselineModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        return JsonSerializer.Serialize(model, SerializerOptions);
    }

    public static AnomalyResult<BaselineModel> Deserialize(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            return AnomalyResult<BaselineModel>.Fail(
                AnomalyErrorKind.DeserializationFailed,
                $"Failed to deserialize baseline: {ex.Message}");
        }

        using (document)
        {
            var root = document.RootElement;

            if (!root.TryGetProperty("version", out var versionElement) ||
                versionElement.ValueKind != JsonValueKind.String)
            {
                return AnomalyResult<BaselineModel>.Fail(
                    AnomalyErrorKind.BaselineCorrupt,
                    "Unsupported baseline version: (missing)");
            }

            var version = versionElement.GetString();
            if (version != SupportedVersion)
            {
                return AnomalyResult<BaselineModel>.Fail(
                    AnomalyErrorKind.BaselineCorrupt,
                    $"Unsupported baseline version: {version}");
            }

            if (!root.TryGetProperty("kind", out var kindElement) ||
                kindElement.ValueKind != JsonValueKind.String)
            {
                return AnomalyResult<BaselineModel>.Fail(
                    AnomalyErrorKind.BaselineCorrupt,
                    "Invalid baseline kind: (missing)");
            }

            var kind = kindElement.GetString();
            if (kind != SupportedKind)
            {
                return AnomalyResult<BaselineModel>.Fail(
                    AnomalyErrorKind.BaselineCorrupt,
                    $"Invalid baseline kind: {kind}");
            }
        }

        BaselineModel? model;
        try
        {
            model = JsonSerializer.Deserialize<BaselineModel>(json, DeserializerOptions);
        }
        catch (JsonException ex)
        {
            return AnomalyResult<BaselineModel>.Fail(
                AnomalyErrorKind.DeserializationFailed,
                $"Failed to deserialize baseline: {ex.Message}");
        }

        if (model is null)
        {
            return AnomalyResult<BaselineModel>.Fail(
                AnomalyErrorKind.DeserializationFailed,
                "Deserialization returned null.");
        }

        return AnomalyResult<BaselineModel>.Ok(model);
    }
}
