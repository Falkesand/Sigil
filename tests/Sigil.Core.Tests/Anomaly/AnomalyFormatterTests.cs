using System.Globalization;
using System.Text.Json;
using Sigil.Anomaly;

namespace Sigil.Core.Tests.Anomaly;

public class AnomalyFormatterTests
{
    // ── FormatText ──────────────────────────────────────────────────

    [Fact]
    public void FormatText_with_no_findings_shows_no_anomalies()
    {
        var report = CreateReport();

        var text = AnomalyFormatter.FormatText(report);

        Assert.Contains("No anomalies detected", text);
    }

    [Fact]
    public void FormatText_with_findings_shows_severity_and_message()
    {
        var finding = CreateFinding(
            severity: AnomalySeverity.Warning,
            message: "Unexpected signer detected");
        var report = CreateReport(finding);

        var text = AnomalyFormatter.FormatText(report);

        Assert.Contains("[WARNING]", text);
        Assert.Contains("Unexpected signer detected", text);
    }

    [Fact]
    public void FormatText_groups_findings_by_severity_critical_first()
    {
        var info = CreateFinding(ruleName: "InfoRule", severity: AnomalySeverity.Info, message: "Info message");
        var critical = CreateFinding(ruleName: "CriticalRule", severity: AnomalySeverity.Critical, message: "Critical message");
        var warning = CreateFinding(ruleName: "WarningRule", severity: AnomalySeverity.Warning, message: "Warning message");
        var report = CreateReport(info, critical, warning);

        var text = AnomalyFormatter.FormatText(report);

        var criticalIndex = text.IndexOf("[CRITICAL]", StringComparison.Ordinal);
        var warningIndex = text.IndexOf("[WARNING]", StringComparison.Ordinal);
        var infoIndex = text.IndexOf("[INFO]", StringComparison.Ordinal);

        Assert.True(criticalIndex >= 0, "Expected [CRITICAL] in output");
        Assert.True(warningIndex >= 0, "Expected [WARNING] in output");
        Assert.True(infoIndex >= 0, "Expected [INFO] in output");
        Assert.True(criticalIndex < warningIndex, "CRITICAL should appear before WARNING");
        Assert.True(warningIndex < infoIndex, "WARNING should appear before INFO");
    }

    // ── FormatJson ──────────────────────────────────────────────────

    [Fact]
    public void FormatJson_produces_valid_json_with_all_fields()
    {
        var context = new Dictionary<string, string> { ["keyId"] = "sha256:abc" };
        var finding = CreateFinding(
            ruleName: "UnknownSigner",
            severity: AnomalySeverity.Warning,
            message: "Unknown signer",
            context: context);
        var report = CreateReport(finding);

        var json = AnomalyFormatter.FormatJson(report);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("test-artifact", root.GetProperty("artifactName").GetString());
        Assert.Equal(1, root.GetProperty("findingCount").GetInt32());
        Assert.Equal(JsonValueKind.Array, root.GetProperty("findings").ValueKind);

        var firstFinding = root.GetProperty("findings")[0];
        Assert.Equal("UnknownSigner", firstFinding.GetProperty("ruleName").GetString());
        Assert.Equal("warning", firstFinding.GetProperty("severity").GetString());
        Assert.Equal("Unknown signer", firstFinding.GetProperty("message").GetString());
        Assert.Equal("sha256:abc", firstFinding.GetProperty("context").GetProperty("keyId").GetString());
    }

    [Fact]
    public void FormatJson_roundtrip_preserves_findings()
    {
        var finding1 = CreateFinding(
            ruleName: "UnknownSigner",
            severity: AnomalySeverity.Warning,
            message: "Signer not in baseline");
        var finding2 = CreateFinding(
            ruleName: "FrequencyAnomaly",
            severity: AnomalySeverity.Critical,
            message: "Signing frequency spike");
        var report = CreateReport(finding1, finding2);

        var json = AnomalyFormatter.FormatJson(report);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal(2, root.GetProperty("findingCount").GetInt32());

        var findings = root.GetProperty("findings");
        Assert.Equal(2, findings.GetArrayLength());

        Assert.Equal("UnknownSigner", findings[0].GetProperty("ruleName").GetString());
        Assert.Equal("Signer not in baseline", findings[0].GetProperty("message").GetString());

        Assert.Equal("FrequencyAnomaly", findings[1].GetProperty("ruleName").GetString());
        Assert.Equal("critical", findings[1].GetProperty("severity").GetString());
        Assert.Equal("Signing frequency spike", findings[1].GetProperty("message").GetString());
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private static AnomalyReport CreateReport(params AnomalyFinding[] findings)
    {
        return new AnomalyReport
        {
            ArtifactName = "test-artifact",
            Timestamp = DateTimeOffset.Parse("2026-02-12T10:00:00Z", CultureInfo.InvariantCulture),
            Findings = findings.ToList(),
        };
    }

    private static AnomalyFinding CreateFinding(
        string ruleName = "TestRule",
        AnomalySeverity severity = AnomalySeverity.Warning,
        string message = "Test message",
        Dictionary<string, string>? context = null)
    {
        return new AnomalyFinding
        {
            RuleName = ruleName,
            Severity = severity,
            Message = message,
            Context = context,
        };
    }
}
