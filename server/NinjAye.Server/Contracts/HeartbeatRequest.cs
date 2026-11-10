using System.Text.Json;

namespace NinjAye.Server;

public sealed record HeartbeatRequest(
    Guid SessionId,
    uint GameProcessId,
    ulong UptimeSeconds,
    uint DetectionCount,
    uint ReportCount,
    JsonElement Metadata);
