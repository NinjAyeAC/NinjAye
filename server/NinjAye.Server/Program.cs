using NinjAye.Server;

var builder = WebApplication.CreateBuilder(args);
builder.AddNinjAyeServer();

var app = builder.Build();
await app.InitializeNinjAyeServerAsync();

app.UseEndpointGuard();
app.MapNinjAyeEndpoints();
app.Run();
