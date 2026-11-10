using System.Security.Cryptography;

namespace NinjAye.Server;

public static class EndpointHttp
{
    public static async Task<ClientAuthentication?> AuthenticateAsync(
        HttpRequest request,
        IStorage storage,
        ClientSessionService sessions,
        CancellationToken cancellationToken)
    {
        var token = ApiSecurity.ReadBearerToken(request);
        if (!IsClientToken(token))
        {
            return null;
        }

        var tokenHash = ApiSecurity.HashToken(token!);
        var installation = await storage.AuthenticateAsync(
            tokenHash,
            cancellationToken);
        return installation is null
            ? null
            : new ClientAuthentication(
                installation,
                tokenHash,
                sessions.SessionId(installation, tokenHash));
    }

    public static bool IsClientToken(string? token)
    {
        return token is { Length: >= 32 and <= 128 } &&
            token.All(static character => Uri.IsHexDigit(character));
    }

    public static async Task<byte[]> ReadBodyLimitedAsync(
        HttpRequest request,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await request.Body.ReadAsync(
                buffer,
                cancellationToken);
            if (read == 0)
            {
                break;
            }
            if (output.Length > maximumBytes - read)
            {
                throw new ProtocolViolationException(
                    "The request body exceeds its limit.");
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    public static string HashHex(byte[] value)
    {
        return Convert.ToHexString(SHA256.HashData(value))
            .ToLowerInvariant();
    }

    public static bool IsReportFilename(string value)
    {
        return value.Length == 36 &&
            value.All(
                static character =>
                    character is >= 'A' and <= 'Z' or
                    >= '0' and <= '9');
    }
}
