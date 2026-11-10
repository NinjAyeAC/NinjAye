using System.Text.Json;

namespace NinjAye.Server;

public sealed record EventRequest(
    string EventId,
    Guid SessionId,
    string Type,
    int Severity,
    DateTimeOffset OccurredAt,
    uint ProcessId,
    uint ThreadId,
    JsonElement Data);
