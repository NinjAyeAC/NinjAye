namespace NinjAye.Server;

public sealed record EnrollmentResponse(
    Guid InstallationId,
    string Token);
