using System.Collections.Generic;

namespace NinjAye.Server;

public sealed record ParsedStatusRequest(
    uint ServerId,
    string Nonce,
    string DllVersion,
    IReadOnlyDictionary<string, string> Identities)
{
    public string PrimaryClientId => Identities["ClientId"];
}
