using System.Text.Json;

namespace NinjAye.Server;

public sealed record SessionStartRequest(
    Guid SessionId,
    uint ServerId,
    string DllVersion,
    string PrimaryClientId,
    JsonElement Identities,
    string GameName,
    uint GameProcessId,
    string GamePath,
    string DllPath,
    JsonElement Metadata);
