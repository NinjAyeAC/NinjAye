namespace NinjAye.Server;

public sealed record StoredSummary(
    long Installations,
    long Sessions,
    long Events,
    long Reports,
    long Detections,
    long Artifacts);
