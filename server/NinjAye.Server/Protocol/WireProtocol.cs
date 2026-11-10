using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MessagePack;
using MessagePack.Resolvers;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;

namespace NinjAye.Server;

public sealed class WireProtocol : IDisposable
{
    public const string UserAgent =
        "NinjAyeClient/1.0.0";
    public const int MaximumResponseBytes = 4 * 1024 * 1024;
    public const int MaximumFileBytes = 25_000_000;

    private static readonly byte[] _mpneMagic = "MPNE"u8.ToArray();

    private readonly RSA _privateKey;
    private readonly MessagePackSerializerOptions _messagepackOptions;
    private readonly IReadOnlyList<string> _reserved2Keys;
    private readonly uint _eventMask;

    public WireProtocol(IConfiguration configuration)
    {
        var configuredPath = configuration["NinjAye:PrivateKeyPath"];
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            throw new InvalidOperationException(
                "NinjAye:PrivateKeyPath is required. Run " +
                "scripts/generate-dev-keys.ps1 and configure the path " +
                "to the generated private PEM.");
        }

        var path = configuredPath;
        if (!Path.IsPathRooted(path))
            path = Path.Combine(AppContext.BaseDirectory, path);

        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"The NinjAye private key was not found at '{path}'. " +
                "Run scripts/generate-dev-keys.ps1 or configure " +
                "NinjAye:PrivateKeyPath.");
        }

        _privateKey = RSA.Create();
        _privateKey.ImportFromPem(File.ReadAllText(path, Encoding.ASCII));
        if (_privateKey.KeySize != 2048)
        {
            _privateKey.Dispose();
            throw new InvalidOperationException(
                "NinjAye requires an RSA-2048 private key.");
        }

        _messagepackOptions =
            MessagePackSerializerOptions.Standard
                .WithResolver(ContractlessStandardResolver.Instance)
                .WithSecurity(MessagePackSecurity.UntrustedData);
        _reserved2Keys = configuration
            .GetSection("NinjAye:Reserved2")
            .GetChildren()
            .Select(static value => value.Value)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray();
        _eventMask = configuration.GetValue<uint>(
            "NinjAye:Reserved50",
            0x40000);
    }

    public UnwrappedRequest Unwrap(ReadOnlySpan<byte> body)
    {
        const int fixedSize = 4 + 12 + 16 + 256;
        if (body.Length <= fixedSize ||
            !body[..4].SequenceEqual(_mpneMagic))
        {
            throw new ProtocolViolationException(
                "The request is not an MPNE envelope.");
        }

        var gcmNonce = body.Slice(4, 12).ToArray();
        var tag = body.Slice(16, 16).ToArray();
        var wrappedKey = body.Slice(32, 256).ToArray();
        var ciphertext = body[fixedSize..].ToArray();
        byte[] sessionKey;
        try
        {
            sessionKey = _privateKey.Decrypt(
                wrappedKey,
                RSAEncryptionPadding.OaepSHA1);
        }
        catch (CryptographicException exception)
        {
            throw new ProtocolViolationException(
                "RSA-OAEP unwrap failed.",
                exception);
        }

        if (sessionKey.Length != 32)
            throw new ProtocolViolationException(
                "The wrapped AES key is not 32 bytes.");

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(sessionKey, tag.Length);
            aes.Decrypt(gcmNonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException exception)
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            throw new ProtocolViolationException(
                "AES-256-GCM authentication failed.",
                exception);
        }

        return new UnwrappedRequest(
            sessionKey,
            gcmNonce,
            plaintext);
    }

    public byte[] WrapStatusResponse(
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> plaintext)
    {
        if (sessionKey.Length != 32)
            throw new ArgumentException(
                "The session key must be 32 bytes.",
                nameof(sessionKey));

        var responseNonce = RandomNumberGenerator.GetBytes(12);
        while (responseNonce.AsSpan().SequenceEqual(requestNonce))
            responseNonce = RandomNumberGenerator.GetBytes(12);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(sessionKey.ToArray(), tag.Length))
            aes.Encrypt(responseNonce, plaintext, ciphertext, tag);

        var body = new byte[4 + 12 + 16 + ciphertext.Length];
        _mpneMagic.CopyTo(body, 0);
        responseNonce.CopyTo(body, 4);
        tag.CopyTo(body, 16);
        ciphertext.CopyTo(body, 32);
        return body;
    }

    public Dictionary<string, object?> DeserializeMap(
        ReadOnlySpan<byte> plaintext)
    {
        try
        {
            return MessagePackSerializer.Deserialize<
                Dictionary<string, object?>>(
                plaintext.ToArray(),
                _messagepackOptions);
        }
        catch (Exception exception) when (
            exception is MessagePackSerializationException or
            InvalidOperationException or
            ArgumentException)
        {
            throw new ProtocolViolationException(
                "MessagePack map parsing failed.",
                exception);
        }
    }

    public byte[] SerializeMap(Dictionary<string, object?> value)
    {
        return MessagePackSerializer.Serialize(
            value,
            _messagepackOptions);
    }

    public ParsedStatusRequest ParseStatusRequest(
        Dictionary<string, object?> value)
    {
        var serverId = RequireUnsigned(value, "ServerId");
        var nonce = RequireString(value, "Nonce");
        var dllVersion = RequireString(value, "DllVersion");
        if (!IsHex(nonce, 32))
            throw new ProtocolViolationException("Nonce is not 32 hex digits.");
        if (dllVersion.Length is < 1 or > 128)
            throw new ProtocolViolationException("DllVersion is invalid.");

        var identities = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in _identityNames)
        {
            var identity = RequireString(value, name);
            if (!IsHex(identity, 32))
            {
                throw new ProtocolViolationException(
                    $"{name} is not a 32-digit hexadecimal identity.");
            }
            identities.Add(name, identity.ToUpperInvariant());
        }

        return new ParsedStatusRequest(
            checked((uint)serverId),
            nonce,
            dllVersion,
            identities);
    }

    public byte[] BuildStatusResponse(string nonce)
    {
        static Dictionary<string, object?> Row(
            string key,
            string value)
        {
            return new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                [key] = value,
            };
        }

        var blacklisted = Enumerable.Range(0, 20)
            .Select(
                index => new Dictionary<string, object?>(
                    StringComparer.Ordinal)
                {
                    ["MD5"] = FixtureHex(index),
                    ["Status"] = 0,
                })
            .ToList();
        var reserved1 = Enumerable.Range(0, 20)
            .Select(index => Row("String1", $"fixture/{index:D2}"))
            .ToList();
        var reserved2 = _reserved2Keys
            .Select(value => Row("String1", value))
            .ToList();
        var value = new Dictionary<string, object?>(
            StringComparer.Ordinal)
        {
            ["Nonce"] = nonce,
            ["Status"] = 0,
            ["BlacklistedMD5s"] = blacklisted,
            ["Reserved1"] = reserved1,
            ["Reserved2"] = reserved2,
            ["Reserved3"] = new List<object?>(),
            ["Reserved4"] = new List<object?>(),
            ["Reserved50"] = _eventMask,
        };
        return SerializeMap(value);
    }

    public static CacheEvent ParseCacheEvent(ReadOnlySpan<byte> body)
    {
        if (body.Length != 60)
            throw new ProtocolViolationException(
                "event.php requires one exact 60-byte cache record.");

        var seed = BinaryPrimitives.ReadUInt32LittleEndian(body);
        var header = body.Slice(4, 56).ToArray();
        var state = seed == 0 ? 0xA12F6C3Du : seed;
        for (var index = 0; index < header.Length; ++index)
        {
            state = unchecked(state * 1664525u + 1013904223u);
            header[index] ^= (byte)(state >> 24);
        }

        var headerSpan = header.AsSpan();
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(headerSpan);
        var version = BinaryPrimitives.ReadUInt16LittleEndian(
            headerSpan[4..]);
        var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(
            headerSpan[6..]);
        if (magic != 0x8D3C51A7u ||
            version != 1 ||
            headerSize != 56)
        {
            throw new ProtocolViolationException(
                "The cache record header is invalid.");
        }

        var fileTime = BinaryPrimitives.ReadUInt64LittleEndian(
            headerSpan[8..]);
        var processId = BinaryPrimitives.ReadUInt32LittleEndian(
            headerSpan[16..]);
        var threadId = BinaryPrimitives.ReadUInt32LittleEndian(
            headerSpan[20..]);
        var ticks = BinaryPrimitives.ReadUInt64LittleEndian(
            headerSpan[24..]);
        var argument0 = BinaryPrimitives.ReadUInt32LittleEndian(
            headerSpan[32..]);
        var argument2 = BinaryPrimitives.ReadUInt64LittleEndian(
            headerSpan[36..]);
        var argument1 = BinaryPrimitives.ReadUInt32LittleEndian(
            headerSpan[44..]);
        var serverId = BinaryPrimitives.ReadUInt32LittleEndian(
            headerSpan[48..]);
        var build = BinaryPrimitives.ReadUInt32LittleEndian(
            headerSpan[52..]);

        DateTimeOffset occurredAt;
        try
        {
            occurredAt = new DateTimeOffset(
                DateTime.FromFileTimeUtc(checked((long)fileTime)));
        }
        catch (ArgumentOutOfRangeException)
        {
            occurredAt = DateTimeOffset.UtcNow;
        }
        catch (OverflowException)
        {
            occurredAt = DateTimeOffset.UtcNow;
        }

        return new CacheEvent(
            seed,
            occurredAt,
            processId,
            threadId,
            ticks,
            argument0,
            argument1,
            argument2,
            serverId,
            build);
    }

    public static async Task<MultipartFile> ReadMultipartFileAsync(
        HttpRequest request,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        if (!MediaTypeHeaderValue.TryParse(
                request.ContentType,
                out var mediaType) ||
            !mediaType.MediaType.Equals(
                "multipart/form-data",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ProtocolViolationException(
                "A multipart/form-data request is required.");
        }

        var boundary = HeaderUtilities.RemoveQuotes(
            mediaType.Boundary).Value;
        if (string.IsNullOrWhiteSpace(boundary))
            throw new ProtocolViolationException(
                "The multipart boundary is missing.");

        var reader = new MultipartReader(boundary, request.Body)
        {
            BodyLengthLimit = maximumBytes + 65_536,
            HeadersLengthLimit = 65_536,
        };
        var section = await reader.ReadNextSectionAsync(cancellationToken);
        if (section is null ||
            !ContentDispositionHeaderValue.TryParse(
                section.ContentDisposition,
                out var disposition))
        {
            throw new ProtocolViolationException(
                "The multipart file section is missing.");
        }
        if (!disposition.DispositionType.Equals(
                "form-data",
                StringComparison.OrdinalIgnoreCase) ||
            !HeaderUtilities.RemoveQuotes(disposition.Name).Equals(
                "file",
                StringComparison.Ordinal))
        {
            throw new ProtocolViolationException(
                "The multipart field must be named file.");
        }

        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await section.Body.ReadAsync(
                buffer,
                cancellationToken);
            if (read == 0)
                break;
            if (output.Length > maximumBytes - read)
                throw new ProtocolViolationException(
                    "The multipart payload exceeds its limit.");
            output.Write(buffer, 0, read);
        }

        return new MultipartFile(
            HeaderUtilities.RemoveQuotes(disposition.FileName).Value ?? "",
            section.ContentType ?? "",
            output.ToArray());
    }

    public static JsonElement ToJson(Dictionary<string, object?> value)
    {
        return JsonSerializer.SerializeToElement(ToPlain(value));
    }

    public static string? FindString(
        Dictionary<string, object?> value,
        string name)
    {
        return value.TryGetValue(name, out var item)
            ? item as string
            : null;
    }

    public void Dispose()
    {
        _privateKey.Dispose();
    }

    private static readonly string[] _identityNames =
    {
        "ClientId",
        "ClientIdV2",
        "ClientIdV3",
        "ClientIdV4",
        "ClientIdV5",
    };

    private static ulong RequireUnsigned(
        Dictionary<string, object?> value,
        string name)
    {
        if (!value.TryGetValue(name, out var item))
            throw new ProtocolViolationException($"{name} is missing.");
        try
        {
            return Convert.ToUInt64(item, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (
            exception is FormatException or InvalidCastException or
            OverflowException)
        {
            throw new ProtocolViolationException(
                $"{name} is not an unsigned integer.",
                exception);
        }
    }

    private static string RequireString(
        Dictionary<string, object?> value,
        string name)
    {
        if (value.TryGetValue(name, out var item) && item is string text)
            return text;
        throw new ProtocolViolationException($"{name} is missing.");
    }

    private static bool IsHex(string value, int length)
    {
        return value.Length == length &&
            value.All(static character => Uri.IsHexDigit(character));
    }

    private static string FixtureHex(int index)
    {
        var material = SHA256.HashData(
            Encoding.UTF8.GetBytes($"ninjaye-fixture:{index:D4}"));
        return Convert.ToHexString(material.AsSpan(0, 16));
    }

    private static object? ToPlain(object? value)
    {
        if (value is null)
            return null;
        if (value is Dictionary<string, object?> dictionary)
        {
            return dictionary.ToDictionary(
                static pair => pair.Key,
                static pair => ToPlain(pair.Value),
                StringComparer.Ordinal);
        }
        if (value is IEnumerable<KeyValuePair<string, object?>> pairs)
        {
            return pairs.ToDictionary(
                static pair => pair.Key,
                static pair => ToPlain(pair.Value),
                StringComparer.Ordinal);
        }
        if (value is System.Collections.IDictionary dictionaryValue)
        {
            var output = new Dictionary<string, object?>(
                StringComparer.Ordinal);
            foreach (System.Collections.DictionaryEntry pair in dictionaryValue)
            {
                output[Convert.ToString(
                    pair.Key,
                    CultureInfo.InvariantCulture) ?? ""] =
                    ToPlain(pair.Value);
            }
            return output;
        }
        if (value is System.Collections.IEnumerable sequence &&
            value is not string)
        {
            return sequence.Cast<object?>()
                .Select(ToPlain)
                .ToArray();
        }
        if (value is byte[] bytes)
            return Convert.ToBase64String(bytes);
        return value;
    }
}
