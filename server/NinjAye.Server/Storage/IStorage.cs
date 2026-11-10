namespace NinjAye.Server;

public interface IStorage
{
    Task InitializeAsync(CancellationToken cancellationToken);

    Task<InstallationIdentity> EnrollAsync(
        string installId,
        string machineLabel,
        byte[] tokenHash,
        CancellationToken cancellationToken);

    Task<InstallationIdentity?> AuthenticateAsync(
        byte[] tokenHash,
        CancellationToken cancellationToken);

    Task StartSessionAsync(
        InstallationIdentity installation,
        SessionStartRequest request,
        CancellationToken cancellationToken);

    Task<bool> HeartbeatAsync(
        InstallationIdentity installation,
        HeartbeatRequest request,
        CancellationToken cancellationToken);

    Task<bool> RecordSessionActivityAsync(
        InstallationIdentity installation,
        SessionActivityRequest request,
        CancellationToken cancellationToken);

    Task<bool> SessionBelongsAsync(
        InstallationIdentity installation,
        Guid sessionId,
        CancellationToken cancellationToken);

    Task<long> InsertEventAsync(
        InstallationIdentity installation,
        EventRequest request,
        CancellationToken cancellationToken);

    Task<long> InsertReportAsync(
        InstallationIdentity installation,
        ReportRequest request,
        CancellationToken cancellationToken);

    Task<long> InsertArtifactAsync(
        InstallationIdentity installation,
        ArtifactRequest request,
        CancellationToken cancellationToken);

    Task<StoredSummary> GetSummaryAsync(
        CancellationToken cancellationToken);
}
