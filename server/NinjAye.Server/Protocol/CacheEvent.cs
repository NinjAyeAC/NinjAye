namespace NinjAye.Server;

public sealed record CacheEvent(
    uint Seed,
    DateTimeOffset OccurredAt,
    uint ProcessId,
    uint ThreadId,
    ulong Ticks,
    uint Argument0,
    uint Argument1,
    ulong Argument2,
    uint ServerId,
    uint Build);
