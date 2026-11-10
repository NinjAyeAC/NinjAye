using System.Security.Cryptography;
using System.Text.Json;

namespace NinjAye.Server;

public sealed class ClientSessionService
{
    public Guid SessionId(
        InstallationIdentity installation,
        byte[] tokenHash)
    {
        var input = new byte[16 + tokenHash.Length];
        installation.InstallationId.TryWriteBytes(input);
        tokenHash.CopyTo(input.AsSpan(16));
        var digest = SHA256.HashData(input);
        return new Guid(digest.AsSpan(0, 16));
    }

    public SessionStartRequest CreateStatusSession(
        InstallationIdentity installation,
        byte[] tokenHash,
        ParsedStatusRequest request)
    {
        var identities = JsonSerializer.SerializeToElement(
            request.Identities);
        var metadata = JsonSerializer.SerializeToElement(
            new
            {
                source = "signed_wire",
                endpoint = "/status2.php",
                protocol = "MPNE/AES-GCM/RSA-OAEP",
                serverId = request.ServerId,
                serverName = request.ServerId == 1
                    ? "Mt2Test"
                    : null,
                dllVersion = request.DllVersion,
                primaryClientId = request.PrimaryClientId,
                identityCount = request.Identities.Count,
                identities = request.Identities,
            });
        return new SessionStartRequest(
            SessionId(installation, tokenHash),
            request.ServerId,
            request.DllVersion,
            request.PrimaryClientId,
            identities,
            "metin2client",
            0,
            "",
            "",
            metadata);
    }

    public async Task EnsureAsync(
        IStorage storage,
        ClientAuthentication authentication,
        CancellationToken cancellationToken)
    {
        if (await storage.SessionBelongsAsync(
                authentication.Installation,
                authentication.SessionId,
                cancellationToken))
        {
            return;
        }

        var metadata = JsonSerializer.SerializeToElement(
            new
            {
                source = "inferred_token_session",
                sessionId = authentication.SessionId,
                createdWithoutStatus = true,
            });
        await storage.StartSessionAsync(
            authentication.Installation,
            new SessionStartRequest(
                authentication.SessionId,
                0,
                "",
                authentication.Installation.InstallId,
                JsonSerializer.SerializeToElement(new { }),
                "metin2client",
                0,
                "",
                "",
                metadata),
            cancellationToken);
    }
}
