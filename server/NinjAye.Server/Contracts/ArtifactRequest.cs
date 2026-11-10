using System.Text.Json;

namespace NinjAye.Server;

public sealed record ArtifactRequest(
    string ArtifactId,
    Guid SessionId,
    string Kind,
    string Name,
    string Sha256,
    long Size,
    DateTimeOffset ObservedAt,
    JsonElement Metadata,
    byte[] Content);
