using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSdJwt.Encoding;

namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Generates key binding JWTs for SD-JWT presentations.
/// Key binding proves the holder controls the private key referenced in the SD-JWT.
/// </summary>
public class KeyBindingGenerator : IKeyBindingGenerator
{
    private readonly TimeProvider timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyBindingGenerator"/> class.
    /// </summary>
    public KeyBindingGenerator()
        : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyBindingGenerator"/> class with dependencies.
    /// </summary>
    /// <param name="timeProvider">The time provider for timestamp generation.</param>
    internal KeyBindingGenerator(TimeProvider timeProvider)
    {
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Creates a key binding JWT signed with the holder's private key.
    /// </summary>
    /// <param name="holderPrivateKey">The holder's ECDSA private key (P-256).</param>
    /// <param name="sdJwtHash">The hash of the SD-JWT being presented.</param>
    /// <param name="audience">The intended audience (verifier).</param>
    /// <param name="nonce">A nonce for replay protection.</param>
    /// <returns>The key binding JWT string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public string CreateKeyBindingJwt(
        byte[] holderPrivateKey,
        string sdJwtHash,
        string audience,
        string nonce)
    {
        ArgumentNullException.ThrowIfNull(holderPrivateKey);
        ArgumentNullException.ThrowIfNull(sdJwtHash);
        ArgumentNullException.ThrowIfNull(audience);
        ArgumentNullException.ThrowIfNull(nonce);

        // Encode header and payload using AOT-compatible serialization
        var headerJson = SerializeKeyBindingHeader();
        var payloadJson = SerializeKeyBindingPayload(
            timeProvider.GetUtcNow().ToUnixTimeSeconds(),
            audience,
            nonce,
            sdJwtHash);

        var headerBase64 = Base64UrlEncoder.Encode(headerJson);
        var payloadBase64 = Base64UrlEncoder.Encode(payloadJson);

        // Sign with holder's private key
        var signingInput = $"{headerBase64}.{payloadBase64}";
        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportECPrivateKey(holderPrivateKey, out _);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid ECDSA private key format", nameof(holderPrivateKey), ex);
        }

        // Validate elliptic curve - only P-256 (ES256) is supported
        if (ecdsa.KeySize != 256)
        {
            throw new ArgumentException(
                $"Only P-256 (256-bit) elliptic curve is supported for ES256. Provided key is {ecdsa.KeySize}-bit.",
                nameof(holderPrivateKey));
        }

        var signature = ecdsa.SignData(
            System.Text.Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256
        );

        var signatureBase64 = Base64UrlEncoder.Encode(signature);
        return $"{signingInput}.{signatureBase64}";
    }

    /// <summary>
    /// Serializes the key binding JWT header using Utf8JsonWriter for AOT compatibility.
    /// Format: {"alg":"ES256","typ":"kb+jwt"}
    /// </summary>
    private string SerializeKeyBindingHeader()
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", "ES256");
            writer.WriteString("typ", "kb+jwt");
            writer.WriteEndObject();
            writer.Flush();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>
    /// Serializes the key binding JWT payload using Utf8JsonWriter for AOT compatibility.
    /// Format: {"iat":timestamp,"aud":"...","nonce":"...","sd_hash":"..."}
    /// </summary>
    private string SerializeKeyBindingPayload(long iat, string aud, string nonce, string sdHash)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("iat", iat);
            writer.WriteString("aud", aud);
            writer.WriteString("nonce", nonce);
            writer.WriteString("sd_hash", sdHash);
            writer.WriteEndObject();
            writer.Flush();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
