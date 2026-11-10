using System.Collections;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace NinjAye.Server;

public sealed class ReportIngestionParser
{
    public ParsedReport Parse(
        string reportFilename,
        Guid sessionId,
        Dictionary<string, object?> report)
    {
        var client = NormalizeClient(
            WireProtocol.ToJson(report));
        var process = ParseJsonField(
            report,
            "ProcessInformation");
        var telemetry = ParseJsonField(report, "Telemetry");
        var detections = ParseDetections(report);
        var createdAt = ParseTimestamp(report);
        var gameProcessId = ReadUInt32(process, "pid");
        var request = new ReportRequest(
            reportFilename,
            sessionId,
            createdAt,
            client,
            process,
            telemetry,
            detections);
        var summary = JsonSerializer.SerializeToElement(
            new
            {
                reportId = reportFilename,
                endpoint = "/upload.php",
                createdAt = createdAt,
                reportType = FindValue(report, "ReportType"),
                serverId = FindValue(report, "ServerId"),
                serverName = FindValue(report, "ServerName"),
                dllVersion = FindValue(report, "DllVersion"),
                dllImageHash = FindValue(report, "DllImageHash"),
                detectionCount = detections.Count,
                process = JsonNode.Parse(process.GetRawText()),
            });
        return new ParsedReport(
            request,
            gameProcessId,
            summary);
    }

    private static JsonElement NormalizeClient(JsonElement value)
    {
        var node = JsonNode.Parse(value.GetRawText());
        if (node is not JsonObject objectNode)
        {
            return JsonSerializer.SerializeToElement(node);
        }

        foreach (var name in new[]
        {
            "ProcessInformation",
            "Telemetry",
            "Detections",
        })
        {
            if (!objectNode.TryGetPropertyValue(name, out var field) ||
                field is not JsonValue fieldValue ||
                !fieldValue.TryGetValue<string>(out var text))
            {
                continue;
            }
            try
            {
                objectNode[name] = JsonNode.Parse(text);
            }
            catch (JsonException)
            {
            }
        }
        return JsonSerializer.SerializeToElement(node);
    }

    private static JsonElement ParseJsonField(
        Dictionary<string, object?> report,
        string name)
    {
        if (!report.TryGetValue(name, out var value))
        {
            return JsonSerializer.SerializeToElement(new { });
        }
        if (value is string json)
        {
            try
            {
                using var document = JsonDocument.Parse(json);
                return document.RootElement.Clone();
            }
            catch (JsonException)
            {
                return JsonSerializer.SerializeToElement(new { });
            }
        }
        return JsonSerializer.SerializeToElement(value);
    }

    private static IReadOnlyList<DetectionRecord> ParseDetections(
        Dictionary<string, object?> report)
    {
        if (!report.TryGetValue("Detections", out var value))
        {
            return Array.Empty<DetectionRecord>();
        }

        try
        {
            JsonElement root;
            if (value is string json)
            {
                using var document = JsonDocument.Parse(json);
                root = document.RootElement.Clone();
            }
            else
            {
                root = JsonSerializer.SerializeToElement(value);
            }
            if (root.ValueKind != JsonValueKind.Array)
            {
                return Array.Empty<DetectionRecord>();
            }

            var output = new List<DetectionRecord>();
            foreach (var row in root.EnumerateArray())
            {
                if (!TryGetUInt32(row, "codeId", out var codeId) ||
                    !TryGetInt32(row, "severity", out var severity) ||
                    !TryGetInt32(
                        row,
                        "confidence",
                        out var confidence))
                {
                    continue;
                }

                var detectedAt = DateTimeOffset.UtcNow;
                if (row.TryGetProperty("detectedAt", out var time) &&
                    time.ValueKind == JsonValueKind.String)
                {
                    DateTimeOffset.TryParse(
                        time.GetString(),
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal,
                        out detectedAt);
                }
                var details =
                    row.TryGetProperty(
                        "details",
                        out var detailValue)
                        ? detailValue.Clone()
                        : JsonSerializer.SerializeToElement(
                            new { });
                output.Add(
                    new DetectionRecord(
                        codeId,
                        severity,
                        confidence,
                        detectedAt,
                        details));
            }
            return output;
        }
        catch (JsonException)
        {
            return Array.Empty<DetectionRecord>();
        }
    }

    private static DateTimeOffset ParseTimestamp(
        Dictionary<string, object?> report)
    {
        return FindValue(report, "Timestamp") is
        { } timestamp &&
            timestamp is string timestampText &&
            DateTimeOffset.TryParse(
                timestampText,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var parsed)
            ? parsed
            : DateTimeOffset.UtcNow;
    }

    private static object? FindValue(
        Dictionary<string, object?> report,
        string name)
    {
        if (report.TryGetValue(name, out var value))
        {
            return ToPlain(value);
        }
        if (!report.TryGetValue(
                "ClientInformation",
                out var clientInformation))
        {
            return null;
        }
        if (clientInformation is Dictionary<string, object?> dictionary &&
            dictionary.TryGetValue(name, out var nestedValue))
        {
            return ToPlain(nestedValue);
        }

        var nested = JsonSerializer.SerializeToElement(clientInformation);
        return nested.ValueKind == JsonValueKind.Object &&
            nested.TryGetProperty(name, out var property)
            ? JsonSerializer.Deserialize<object?>(
                property.GetRawText())
            : null;
    }

    private static object? ToPlain(object? value)
    {
        if (value is null)
        {
            return null;
        }
        if (value is Dictionary<string, object?> dictionary)
        {
            return dictionary.ToDictionary(
                static pair => pair.Key,
                static pair => ToPlain(pair.Value),
                StringComparer.Ordinal);
        }
        if (value is IEnumerable sequence and not string and not byte[])
        {
            return sequence.Cast<object?>()
                .Select(ToPlain)
                .ToArray();
        }
        if (value is byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
        return value;
    }

    private static uint ReadUInt32(
        JsonElement value,
        string name)
    {
        return value.ValueKind == JsonValueKind.Object &&
            value.TryGetProperty(name, out var property) &&
            property.TryGetUInt32(out var result)
            ? result
            : 0;
    }

    private static bool TryGetUInt32(
        JsonElement value,
        string name,
        out uint result)
    {
        result = 0;
        return value.TryGetProperty(name, out var property) &&
            property.TryGetUInt32(out result);
    }

    private static bool TryGetInt32(
        JsonElement value,
        string name,
        out int result)
    {
        result = 0;
        return value.TryGetProperty(name, out var property) &&
            property.TryGetInt32(out result);
    }
}
