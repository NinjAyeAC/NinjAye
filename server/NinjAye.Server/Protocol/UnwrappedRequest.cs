namespace NinjAye.Server;

public sealed record UnwrappedRequest(
    byte[] SessionKey,
    byte[] GcmNonce,
    byte[] Plaintext);
