namespace NinjAye.Server;

public sealed record ClientAuthentication(
    InstallationIdentity Installation,
    byte[] TokenHash,
    Guid SessionId);
