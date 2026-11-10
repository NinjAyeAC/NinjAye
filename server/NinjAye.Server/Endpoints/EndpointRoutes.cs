using System.Security.Cryptography;
using System.Text.Json;

namespace NinjAye.Server;

public static class EndpointRoutes
{
    public static void MapNinjAyeEndpoints(
        this WebApplication app)
    {
        app.MapPost("/status2.php", HandleStatusAsync);
        app.MapPost("/event.php", HandleEventAsync);
        app.MapPost("/upload.php", HandleUploadAsync);
        app.MapPost("/file.php", HandleFileAsync);
    }

    private static async Task<IResult> HandleStatusAsync(
        HttpContext context,
        IStorage storage,
        WireProtocol wire,
        ClientSessionService sessions,
        CancellationToken cancellationToken)
    {
        UnwrappedRequest? unwrapped = null;
        try
        {
            var token =
                ApiSecurity.ReadBearerToken(context.Request);
            if (!EndpointHttp.IsClientToken(token))
            {
                return Results.Unauthorized();
            }
            var tokenHash = ApiSecurity.HashToken(token!);
            var body = await EndpointHttp.ReadBodyLimitedAsync(
                context.Request,
                WireProtocol.MaximumResponseBytes,
                cancellationToken);
            unwrapped = wire.Unwrap(body);
            var document = wire.DeserializeMap(unwrapped.Plaintext);
            var request = wire.ParseStatusRequest(document);
            var installation = await storage.EnrollAsync(
                $"ninjaye:{request.PrimaryClientId.ToLowerInvariant()}",
                request.PrimaryClientId,
                tokenHash,
                cancellationToken);
            await storage.StartSessionAsync(
                installation,
                sessions.CreateStatusSession(
                    installation,
                    tokenHash,
                    request),
                cancellationToken);

            var plaintext =
                wire.BuildStatusResponse(request.Nonce);
            var response = wire.WrapStatusResponse(
                unwrapped.SessionKey,
                unwrapped.GcmNonce,
                plaintext);
            return Results.Bytes(
                response,
                "application/octet-stream");
        }
        catch (ProtocolViolationException exception)
        {
            Console.Error.WriteLine(
                $"status2.php: {exception.Message}");
            return Results.BadRequest();
        }
        finally
        {
            if (unwrapped is not null)
            {
                CryptographicOperations.ZeroMemory(
                    unwrapped.SessionKey);
            }
        }
    }

    private static async Task<IResult> HandleEventAsync(
        HttpContext context,
        IStorage storage,
        ClientSessionService sessions,
        CancellationToken cancellationToken)
    {
        try
        {
            var authentication =
                await EndpointHttp.AuthenticateAsync(
                    context.Request,
                    storage,
                    sessions,
                    cancellationToken);
            if (authentication is null)
            {
                return Results.Unauthorized();
            }

            var body = await EndpointHttp.ReadBodyLimitedAsync(
                context.Request,
                60,
                cancellationToken);
            var cacheEvent = WireProtocol.ParseCacheEvent(body);
            await sessions.EnsureAsync(
                storage,
                authentication,
                cancellationToken);
            var eventId = EndpointHttp.HashHex(body);
            var data = JsonSerializer.SerializeToElement(
                new
                {
                    seed = cacheEvent.Seed,
                    ticks = cacheEvent.Ticks,
                    argument0 = cacheEvent.Argument0,
                    argument1 = cacheEvent.Argument1,
                    argument2 = cacheEvent.Argument2,
                    serverId = cacheEvent.ServerId,
                    build = cacheEvent.Build,
                });
            var eventType =
                $"cache.0x{cacheEvent.Argument0:X8}.0x{cacheEvent.Argument1:X8}";
            await storage.InsertEventAsync(
                authentication.Installation,
                new EventRequest(
                    eventId,
                    authentication.SessionId,
                    eventType,
                    cacheEvent.Argument0 == 9 ? 3 : 1,
                    cacheEvent.OccurredAt,
                    cacheEvent.ProcessId,
                    cacheEvent.ThreadId,
                    data),
                cancellationToken);
            await storage.RecordSessionActivityAsync(
                authentication.Installation,
                new SessionActivityRequest(
                    authentication.SessionId,
                    "/event.php",
                    cacheEvent.ProcessId,
                    cacheEvent.ThreadId,
                    data,
                    EventIncrement: 1),
                cancellationToken);
            return Results.StatusCode(StatusCodes.Status200OK);
        }
        catch (ProtocolViolationException exception)
        {
            Console.Error.WriteLine(
                $"event.php: {exception.Message}");
            return Results.BadRequest();
        }
    }

    private static async Task<IResult> HandleUploadAsync(
        HttpContext context,
        IStorage storage,
        WireProtocol wire,
        ClientSessionService sessions,
        ReportIngestionParser reports,
        CancellationToken cancellationToken)
    {
        UnwrappedRequest? unwrapped = null;
        try
        {
            var authentication =
                await EndpointHttp.AuthenticateAsync(
                    context.Request,
                    storage,
                    sessions,
                    cancellationToken);
            if (authentication is null)
            {
                return Results.Unauthorized();
            }

            var multipart =
                await WireProtocol.ReadMultipartFileAsync(
                    context.Request,
                    WireProtocol.MaximumResponseBytes,
                    cancellationToken);
            if (!EndpointHttp.IsReportFilename(
                    multipart.Filename) ||
                !multipart.ContentType.Equals(
                    "application/octet-stream",
                    StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest();
            }

            unwrapped = wire.Unwrap(multipart.Content);
            var reportMap =
                wire.DeserializeMap(unwrapped.Plaintext);
            await sessions.EnsureAsync(
                storage,
                authentication,
                cancellationToken);
            var parsed = reports.Parse(
                multipart.Filename,
                authentication.SessionId,
                reportMap);
            await storage.InsertReportAsync(
                authentication.Installation,
                parsed.Request,
                cancellationToken);
            await storage.RecordSessionActivityAsync(
                authentication.Installation,
                new SessionActivityRequest(
                    authentication.SessionId,
                    "/upload.php",
                    parsed.GameProcessId,
                    0,
                    parsed.SessionSummary,
                    ReportIncrement: 1,
                    DetectionIncrement:
                        parsed.Request.Detections.Count),
                cancellationToken);
            return Results.StatusCode(StatusCodes.Status200OK);
        }
        catch (ProtocolViolationException exception)
        {
            Console.Error.WriteLine(
                $"upload.php: {exception.Message}");
            return Results.BadRequest();
        }
        finally
        {
            if (unwrapped is not null)
            {
                CryptographicOperations.ZeroMemory(
                    unwrapped.SessionKey);
            }
        }
    }

    private static async Task<IResult> HandleFileAsync(
        HttpContext context,
        IStorage storage,
        ClientSessionService sessions,
        ILogger<FileEndpointLog> logger,
        CancellationToken cancellationToken)
    {
        try
        {
            var authentication =
                await EndpointHttp.AuthenticateAsync(
                    context.Request,
                    storage,
                    sessions,
                    cancellationToken);
            if (authentication is null)
            {
                return Results.Unauthorized();
            }

            var multipart =
                await WireProtocol.ReadMultipartFileAsync(
                    context.Request,
                    WireProtocol.MaximumFileBytes,
                    cancellationToken);
            if (!multipart.Filename.Equals(
                    "application",
                    StringComparison.Ordinal) ||
                !multipart.ContentType.Equals(
                    "application/octet-stream",
                    StringComparison.OrdinalIgnoreCase) ||
                multipart.Content.Length is < 5 or
                    > WireProtocol.MaximumFileBytes)
            {
                return Results.BadRequest();
            }

            await sessions.EnsureAsync(
                storage,
                authentication,
                cancellationToken);
            var sha256 = Convert.ToHexString(
                    SHA256.HashData(multipart.Content))
                .ToLowerInvariant();
            var metadata = JsonSerializer.SerializeToElement(
                new
                {
                    endpoint = "/file.php",
                    field = "file",
                    filename = "application",
                    contentType = multipart.ContentType,
                    size = multipart.Content.Length,
                    sha256,
                });
            var observedAt = DateTimeOffset.UtcNow;
            await storage.InsertArtifactAsync(
                authentication.Installation,
                new ArtifactRequest(
                    sha256,
                    authentication.SessionId,
                    "process_image",
                    "application",
                    sha256,
                    multipart.Content.Length,
                    observedAt,
                    metadata,
                    multipart.Content),
                cancellationToken);
            await storage.RecordSessionActivityAsync(
                authentication.Installation,
                new SessionActivityRequest(
                    authentication.SessionId,
                    "/file.php",
                    0,
                    0,
                    metadata,
                    ArtifactIncrement: 1),
                cancellationToken);
            logger.LogInformation(
                "file.php accepted session={SessionId} size={Size} sha256={Sha256}",
                authentication.SessionId,
                multipart.Content.Length,
                sha256);
            return Results.StatusCode(StatusCodes.Status200OK);
        }
        catch (ProtocolViolationException exception)
        {
            Console.Error.WriteLine(
                $"file.php: {exception.Message}");
            return Results.BadRequest();
        }
    }
}
