namespace NinjAye.Server;

public static class ServerComposition
{
    private static readonly HashSet<string> _supportedPaths =
        new(StringComparer.Ordinal)
        {
            "/status2.php",
            "/event.php",
            "/upload.php",
            "/file.php",
        };

    public static void AddNinjAyeServer(
        this WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(
            options =>
            {
                options.Limits.MaxRequestBodySize =
                    32 * 1024 * 1024;
            });

        var storageMode =
            ReadSetting(builder.Configuration, "Storage") ??
            "memory";
        if (storageMode.Equals(
                "postgres",
                StringComparison.OrdinalIgnoreCase))
        {
            var connectionString =
                builder.Configuration.GetConnectionString(
                    "Postgres") ??
                throw new InvalidOperationException(
                    "ConnectionStrings:Postgres is required for PostgreSQL storage.");
            builder.Services.AddSingleton<IStorage>(
                _ => new PostgresStorage(connectionString));
        }
        else
        {
            builder.Services.AddSingleton<IStorage, MemoryStorage>();
        }

        builder.Services.AddSingleton<WireProtocol>();
        builder.Services.AddSingleton<ClientSessionService>();
        builder.Services.AddSingleton<ReportIngestionParser>();
    }

    public static async Task InitializeNinjAyeServerAsync(
        this WebApplication app)
    {
        await app.Services
            .GetRequiredService<IStorage>()
            .InitializeAsync(app.Lifetime.ApplicationStopping);
    }

    public static void UseEndpointGuard(
        this WebApplication app)
    {
        app.Use(
            async (context, next) =>
            {
                if (!_supportedPaths.Contains(
                        context.Request.Path.Value ?? ""))
                {
                    context.Response.StatusCode =
                        StatusCodes.Status404NotFound;
                    return;
                }
                await next(context);
            });
    }

    private static string? ReadSetting(
        IConfiguration configuration,
        string name)
    {
        return configuration[$"NinjAye:{name}"] ??
            configuration[name];
    }
}
