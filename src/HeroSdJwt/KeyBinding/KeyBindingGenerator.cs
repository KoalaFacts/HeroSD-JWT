using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Generates key binding JWTs for SD-JWT presentations.
/// Key binding proves the holder controls the private key referenced in the SD-JWT.
/// </summary>
public class KeyBindingGenerator : IKeyBindingGenerator
{
    // Serialize the fixed protected header just once. In particular, retain
    // Utf8JsonWriter's exact escaping of "kb+jwt" for byte-compatible proofs.
    private static readonly string _keyBindingHeaderBase64Url = SerializeKeyBindingHeaderBase64Url();

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

        // Every holder binding claim contributes at least one UTF-8 byte per
        // UTF-16 code unit to the signed JSON. Reject values that cannot
        // possibly fit the verifier's 64-KiB compact JWT size limit before
        // reading the clock, serializing JSON, or allocating base64 text.
        if (sdJwtHash.Length > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException("SD-JWT hash is too large for a key-binding JWT.", nameof(sdJwtHash));
        }

        if (audience.Length > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException("Audience is too large for a key-binding JWT.", nameof(audience));
        }

        if (nonce.Length > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException("Nonce is too large for a key-binding JWT.", nameof(nonce));
        }

        if ((long)sdJwtHash.Length + audience.Length + nonce.Length > Constants.MAX_JWT_SIZE_BYTES)
        {
            throw new ArgumentException("Holder binding claims cannot fit within the maximum key-binding JWT size.");
        }

        // Utf8JsonWriter silently replaces unpaired UTF-16 surrogates.
        // Reject them rather than sign a different audience, nonce or hash
        // from what the holder supplied.
        ValidateUtf16(sdJwtHash, nameof(sdJwtHash));
        ValidateUtf16(audience, nameof(audience));
        ValidateUtf16(nonce, nameof(nonce));

        // Serialize the variable payload to UTF-8 once, without a temporary
        // JSON string followed by an additional UTF-8 conversion.
        var headerBase64 = _keyBindingHeaderBase64Url;
        var payloadBase64 = SerializeKeyBindingPayloadBase64Url(
            _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
            audience,
            nonce,
            sdJwtHash);

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

        // Base64url segments contain ASCII only. Encode the signed bytes
        // directly, without allocating an intermediate JWT signing-input string
        // or a UTF-8 byte[] for the common short holder proof.
        var signingInputLength = headerBase64.Length + 1 + payloadBase64.Length;
        const int StackSigningInputLimit = 1024;
        Span<byte> signingInputBytes = signingInputLength <= StackSigningInputLimit
            ? stackalloc byte[signingInputLength]
            : new byte[signingInputLength];
        var headerByteCount = System.Text.Encoding.ASCII.GetBytes(
            headerBase64.AsSpan(), signingInputBytes);
        signingInputBytes[headerByteCount] = (byte)'.';
        var payloadByteCount = System.Text.Encoding.ASCII.GetBytes(
            payloadBase64.AsSpan(), signingInputBytes[(headerByteCount + 1)..]);

        var signature = ecdsa.SignData(
            signingInputBytes[..(headerByteCount + 1 + payloadByteCount)],
            HashAlgorithmName.SHA256);

        var signatureBase64 = Base64UrlEncoder.Encode(signature);
        return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
    }

    private static void ValidateUtf16(string value, string parameterName)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var codeUnit = value[i];
            if (!char.IsSurrogate(codeUnit))
            {
                continue;
            }

            if (!char.IsHighSurrogate(codeUnit) ||
                i + 1 == value.Length ||
                !char.IsLowSurrogate(value[i + 1]))
            {
                throw new ArgumentException(
                    "Holder binding input contains invalid UTF-16.",
                    parameterName);
            }

            i++; // A well-formed high/low pair represents one Unicode scalar.
        }
    }

    // Preserve the original protected-header bytes across all target frameworks.
    private static string SerializeKeyBindingHeaderBase64Url()
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

        return Base64Url.EncodeToString(buffer.WrittenSpan);
    }

    /// <summary>
    /// Serializes the key binding JWT payload using Utf8JsonWriter for AOT compatibility.
    /// Format: {"iat":timestamp,"aud":"...","nonce":"...","sd_hash":"..."}
    /// </summary>
    private static string SerializeKeyBindingPayloadBase64Url(long iat, string aud, string nonce, string sdHash)
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

        return Base64Url.EncodeToString(buffer.WrittenSpan);
    }
}
