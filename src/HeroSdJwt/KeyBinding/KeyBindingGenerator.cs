using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Generates key binding JWTs for SD-JWT presentations.
/// Key binding proves the holder controls the private key referenced in the SD-JWT.
/// </summary>
public class KeyBindingGenerator : IKeyBindingGenerator
{
    private readonly TimeProvider _timeProvider;

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
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Creates a key binding JWT signed with the holder's private key.
    /// </summary>
    /// <param name="holderPrivateKey">The holder's P-256 private key in SEC1 or PKCS#8 format.</param>
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

        // Reject unusable holder proofs before serialization or signing. A
        // blank hash cannot bind a presentation, and the verifier requires a
        // non-blank audience and nonce.
        if (string.IsNullOrWhiteSpace(sdJwtHash))
        {
            throw new ArgumentException("SD-JWT hash cannot be empty or whitespace.", nameof(sdJwtHash));
        }

        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ArgumentException("Audience cannot be empty or whitespace.", nameof(audience));
        }

        if (string.IsNullOrWhiteSpace(nonce))
        {
            throw new ArgumentException("Nonce cannot be empty or whitespace.", nameof(nonce));
        }

        // Encode header and payload using AOT-compatible serialization
        var headerJson = SerializeKeyBindingHeader();
        var payloadJson = SerializeKeyBindingPayload(
            _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
            audience,
            nonce,
            sdJwtHash);

        var headerBase64 = Base64UrlEncoder.Encode(headerJson);
        var payloadBase64 = Base64UrlEncoder.Encode(payloadJson);

        // ES256 emits a 64-byte IEEE P1363 signature (86 unpadded base64url
        // characters). Reject proofs that cannot pass the verifier's existing
        // compact-JWT size gate before importing the holder key or signing.
        const int Es256SignatureBase64UrlLength = 86;
        if ((long)headerBase64.Length + payloadBase64.Length + 2 + Es256SignatureBase64UrlLength >
            Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException(
                $"Key binding JWT exceeds the maximum allowed size of {Constants.MAX_JWT_SIZE_BYTES} bytes.");
        }

        // Sign with holder's private key
        var signingInput = $"{headerBase64}.{payloadBase64}";
        using var ecdsa = ECDsa.Create();
        try
        {
            int bytesRead;
            try
            {
                // Existing callers provide SEC1 ECPrivateKey data.
                ecdsa.ImportECPrivateKey(holderPrivateKey, out bytesRead);
            }
            catch (CryptographicException)
            {
                // KeyGenerator.GenerateEcdsaKeyPair exports PKCS#8, not SEC1.
                // Both are standard private-key containers for P-256.
                ecdsa.ImportPkcs8PrivateKey(holderPrivateKey, out bytesRead);
            }

            // Import methods accept a valid ASN.1 prefix. Do not sign using
            // a private key with unconsumed attacker-controlled suffix bytes.
            if (bytesRead != holderPrivateKey.Length)
            {
                throw new ArgumentException(
                    "ECDSA private key must contain exactly one ASN.1 key.",
                    nameof(holderPrivateKey));
            }
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid ECDSA private key format", nameof(holderPrivateKey), ex);
        }
        catch (PlatformNotSupportedException ex)
        {
            // The platform may refuse secp256k1 before the named-curve guard runs.
            throw new ArgumentException("Unsupported ECDSA private key curve", nameof(holderPrivateKey), ex);
        }

        // Validate elliptic curve - only P-256 (ES256) is supported
        if (!EcCurveGuard.IsP256(ecdsa))
        {
            throw new ArgumentException(
                "Only the named NIST P-256 elliptic curve is supported for ES256.",
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
