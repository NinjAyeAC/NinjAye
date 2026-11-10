using System.Collections.Concurrent;
using System.Text.Json;

namespace NinjAye.Server;

public sealed class MemoryStorage : IStorage
{
    private sealed class SessionMemory
    {
        public SessionMemory(
            Guid installationId,
            SessionStartRequest request)
        {
            InstallationId = installationId;
            GameProcessId = request.GameProcessId;
            LastEndpoint = "/status2.php";
            Metadata = request.Metadata.Clone();
        }

        public object Sync { get; } = new();
        public Guid InstallationId { get; }
        public uint GameProcessId { get; set; }
        public string LastEndpoint { get; set; }
        public long EventCount { get; set; }
        public long ReportCount { get; set; }
        public long DetectionCount { get; set; }
        public long ArtifactCount { get; set; }
        public JsonElement Metadata { get; set; }
    }

    private readonly ConcurrentDictionary<
        string,
        InstallationIdentity> _installations =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte>
        _countedInstallations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<
        string,
        InstallationIdentity> _tokens =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Guid, SessionMemory> _sessions =
        new();
    private long _installationCount;
    private long _eventCount;
    private long _reportCount;
    private long _detectionCount;
    private long _artifactCount;

    public Task InitializeAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public Task<InstallationIdentity> EnrollAsync(
        string installId,
        string machineLabel,
        byte[] tokenHash,
        CancellationToken cancellationToken)
    {
        var identity = _installations.GetOrAdd(
            installId,
            static value => new InstallationIdentity(
                Guid.NewGuid(),
                value));
        if (_countedInstallations.TryAdd(installId, 0))
        {
            Interlocked.Increment(ref _installationCount);
        }
        _tokens[Convert.ToHexString(tokenHash)] = identity;
        return Task.FromResult(identity);
    }

    public Task<InstallationIdentity?> AuthenticateAsync(
        byte[] tokenHash,
        CancellationToken cancellationToken)
    {
        _tokens.TryGetValue(
            Convert.ToHexString(tokenHash),
            out var identity);
        return Task.FromResult(identity);
    }

    public Task StartSessionAsync(
        InstallationIdentity installation,
        SessionStartRequest request,
        CancellationToken cancellationToken)
    {
        var candidate = new SessionMemory(
            installation.InstallationId,
            request);
        if (_sessions.TryAdd(request.SessionId, candidate))
        {
            return Task.CompletedTask;
        }

        var session = _sessions[request.SessionId];
        lock (session.Sync)
        {
            if (session.InstallationId != installation.InstallationId)
            {
                throw new InvalidOperationException(
                    "Session belongs to a different installation.");
            }
            if (request.GameProcessId != 0)
            {
                session.GameProcessId = request.GameProcessId;
            }
            session.LastEndpoint = "/status2.php";
            session.Metadata = request.Metadata.Clone();
        }
        return Task.CompletedTask;
    }

    public Task<bool> HeartbeatAsync(
        InstallationIdentity installation,
        HeartbeatRequest request,
        CancellationToken cancellationToken)
    {
        if (!_sessions.TryGetValue(
                request.SessionId,
                out var session) ||
            session.InstallationId != installation.InstallationId)
        {
            return Task.FromResult(false);
        }
        lock (session.Sync)
        {
            if (request.GameProcessId != 0)
            {
                session.GameProcessId = request.GameProcessId;
            }
            session.DetectionCount = request.DetectionCount;
            session.ReportCount = request.ReportCount;
            session.Metadata = request.Metadata.Clone();
        }
        return Task.FromResult(true);
    }

    public Task<bool> RecordSessionActivityAsync(
        InstallationIdentity installation,
        SessionActivityRequest request,
        CancellationToken cancellationToken)
    {
        if (!_sessions.TryGetValue(
                request.SessionId,
                out var session) ||
            session.InstallationId != installation.InstallationId)
        {
            return Task.FromResult(false);
        }
        lock (session.Sync)
        {
            if (request.GameProcessId != 0)
            {
                session.GameProcessId = request.GameProcessId;
            }
            session.LastEndpoint = request.Endpoint;
            session.EventCount += request.EventIncrement;
            session.ReportCount += request.ReportIncrement;
            session.DetectionCount += request.DetectionIncrement;
            session.ArtifactCount += request.ArtifactIncrement;
            session.Metadata = request.Data.Clone();
        }
        return Task.FromResult(true);
    }

    public Task<bool> SessionBelongsAsync(
        InstallationIdentity installation,
        Guid sessionId,
        CancellationToken cancellationToken)
    {
        var exists =
            _sessions.TryGetValue(sessionId, out var session) &&
            session.InstallationId == installation.InstallationId;
        return Task.FromResult(exists);
    }

    public Task<long> InsertEventAsync(
        InstallationIdentity installation,
        EventRequest request,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(
            Interlocked.Increment(ref _eventCount));
    }

    public Task<long> InsertReportAsync(
        InstallationIdentity installation,
        ReportRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Detections.Count > 0)
        {
            Interlocked.Add(
                ref _detectionCount,
                request.Detections.Count);
        }
        return Task.FromResult(
            Interlocked.Increment(ref _reportCount));
    }

    public Task<long> InsertArtifactAsync(
        InstallationIdentity installation,
        ArtifactRequest request,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(
            Interlocked.Increment(ref _artifactCount));
    }

    public Task<StoredSummary> GetSummaryAsync(
        CancellationToken cancellationToken)
    {
        return Task.FromResult(
            new StoredSummary(
                Interlocked.Read(ref _installationCount),
                _sessions.Count,
                Interlocked.Read(ref _eventCount),
                Interlocked.Read(ref _reportCount),
                Interlocked.Read(ref _detectionCount),
                Interlocked.Read(ref _artifactCount)));
    }
}
