using System.Text.Json;

namespace NinjAye.Server;

public sealed record ParsedReport(
    ReportRequest Request,
    uint GameProcessId,
    JsonElement SessionSummary);
