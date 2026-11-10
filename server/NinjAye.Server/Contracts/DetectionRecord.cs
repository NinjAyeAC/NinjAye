using System.Text.Json;

namespace NinjAye.Server;

public sealed record DetectionRecord(
    uint CodeId,
    int Severity,
    int Confidence,
    DateTimeOffset DetectedAt,
    JsonElement Details);
