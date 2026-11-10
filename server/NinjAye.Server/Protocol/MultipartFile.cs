namespace NinjAye.Server;

public sealed record MultipartFile(
    string Filename,
    string ContentType,
    byte[] Content);
