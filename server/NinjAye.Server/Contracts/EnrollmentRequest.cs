namespace NinjAye.Server;

public sealed record EnrollmentRequest(
    string InstallId,
    string MachineLabel,
    string ApiVersion);
