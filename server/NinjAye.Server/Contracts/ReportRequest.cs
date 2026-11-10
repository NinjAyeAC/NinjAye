using System.Collections.Generic;
using System.Text.Json;

namespace NinjAye.Server;

public sealed record ReportRequest(
    string ReportId,
    Guid SessionId,
    DateTimeOffset CreatedAt,
    JsonElement Client,
    JsonElement Process,
    JsonElement Telemetry,
    IReadOnlyList<DetectionRecord> Detections);
