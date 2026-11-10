using System.Text.Json;

namespace NinjAye.Server;

public sealed record SessionActivityRequest(
    Guid SessionId,
    string Endpoint,
    uint GameProcessId,
    uint ThreadId,
    JsonElement Data,
    long EventIncrement = 0,
    long ReportIncrement = 0,
    long DetectionIncrement = 0,
    long ArtifactIncrement = 0);
