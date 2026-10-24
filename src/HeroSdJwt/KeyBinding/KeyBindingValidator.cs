using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Validates key binding JWTs to prove holder possession of private key.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="KeyBindingValidator"/> class with dependencies.
/// </remarks>
/// <param name="timeProvider">The time provider for temporal validation.</param>
public class KeyBindingValidator(TimeProvider timeProvider) : IKeyBindingValidator
{
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyBindingValidator"/> class.
    /// </summary>
    public KeyBindingValidator()
        : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Validates a key binding JWT against the holder's public key.
    /// </summary>
    /// <param name="keyBindingJwt">The key binding JWT to validate.</param>
    /// <param name="holderPublicKey">The holder's public key from the cnf claim.</param>
    /// <param name="expectedSdJwtHash">The expected SD-JWT hash.</param>
    /// <param name="expectedAudience">The expected audience.</param>
    /// <param name="expectedNonce">The expected nonce.</param>
    /// <returns>True if valid; otherwise, false.</returns>
    public bool ValidateKeyBinding(
        string keyBindingJwt,
        byte[] holderPublicKey,
        string expectedSdJwtHash,
        string? expectedAudience = null,
        string? expectedNonce = null)
    {
        var audiences = expectedAudience == null
            ? Array.Empty<string>()
            : [expectedAudience];

        return ValidateKeyBinding(
            keyBindingJwt,
            holderPublicKey,
            expectedSdJwtHash,
            audiences,
            expectedNonce);
    }

    /// <summary>
    /// Validates a key binding JWT against the holder's public key using multiple expected audiences.
    /// </summary>
    /// <param name="keyBindingJwt">The key binding JWT to validate.</param>
    /// <param name="holderPublicKey">The holder's public key from the cnf claim.</param>
    /// <param name="expectedSdJwtHash">The expected SD-JWT hash.</param>
    /// <param name="expectedAudiences">The acceptable audiences.</param>
    /// <param name="expectedNonce">The expected nonce.</param>
    /// <returns>True if valid; otherwise, false.</returns>
    public bool ValidateKeyBinding(
        string keyBindingJwt,
        byte[] holderPublicKey,
        string expectedSdJwtHash,
        IReadOnlyCollection<string> expectedAudiences,
        string? expectedNonce = null)
    {
        ArgumentNullException.ThrowIfNull(keyBindingJwt);
        ArgumentNullException.ThrowIfNull(holderPublicKey);
        ArgumentNullException.ThrowIfNull(expectedSdJwtHash);

        ArgumentNullException.ThrowIfNull(expectedAudiences);

        // Direct callers bypass the SD-JWT presentation size gate. Bound a
        // compact KB-JWT before splitting or decoding untrusted input.
        if (keyBindingJwt.Length > Constants.MAX_JWT_SIZE_BYTES)
        {
            return false;
        }

        if (expectedAudiences.Count == 0)
        {
            return false; // Spec requires audience binding
        }

        var expectedAudienceSet = new HashSet<string>(StringComparer.Ordinal);
        foreach (var audience in expectedAudiences)
        {
            if (!string.IsNullOrWhiteSpace(audience))
            {
                _ = expectedAudienceSet.Add(audience);
            }
        }

        if (expectedAudienceSet.Count == 0)
        {
            return false; // Spec requires at least one non-empty audience
        }

        if (string.IsNullOrWhiteSpace(expectedNonce))
        {
            return false; // Spec requires nonce binding
        }

        try
        {
            // Parse JWT
            var parts = keyBindingJwt.Split('.');
            if (parts.Length != 3)
            {
                return false;
            }

            var headerBase64 = parts[0];
            var payloadBase64 = parts[1];
            var signatureBase64 = parts[2];

            // Decode and validate header
            var headerJson = Base64UrlEncoder.DecodeString(headerBase64);
            using var headerDocument = JsonDocument.Parse(headerJson);
            var header = headerDocument.RootElement;

            // Only ES256 key-binding JWTs are supported. Reject a missing or
            // contradictory JOSE algorithm even if the bytes verify as ES256.
            if (header.ValueKind != JsonValueKind.Object ||
                !header.TryGetProperty("alg", out var algElement) ||
                algElement.ValueKind != JsonValueKind.String ||
                algElement.GetString() != "ES256" ||
                !header.TryGetProperty("typ", out var typElement) ||
                typElement.ValueKind != JsonValueKind.String ||
                typElement.GetString() != "kb+jwt")
            {
                return false;
            }

            // No JOSE critical extensions (including RFC 7797's b64 override) are
            // implemented. Never accept a valid signature while ignoring a required
            // header interpretation; b64 also requires critical handling.
            if (header.TryGetProperty("crit", out _) ||
                header.TryGetProperty("b64", out _))
            {
                return false;
            }

            // Decode and validate payload
            var payloadJson = Base64UrlEncoder.DecodeString(payloadBase64);
            using var payloadDocument = JsonDocument.Parse(payloadJson);
            var payload = payloadDocument.RootElement;
            if (payload.ValueKind != JsonValueKind.Object)
            {
                return false; // The KB-JWT payload must be a JSON object.
            }

            // Validate sd_hash claim exists and matches expected value
            if (!payload.TryGetProperty("sd_hash", out var sdHashElement) ||
                sdHashElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var sdHashClaim = sdHashElement.GetString();
            if (sdHashClaim != expectedSdJwtHash)
            {
                return false; // SD-JWT hash mismatch
            }

            // RFC 9901 Section 4.3 requires exactly one string audience in a KB-JWT.
            // The verifier may be configured with multiple acceptable audiences,
            // but the holder proof itself must not contain an audience array.
            if (!payload.TryGetProperty("aud", out var audElement) ||
                audElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var audience = audElement.GetString();
            if (string.IsNullOrEmpty(audience) || !expectedAudienceSet.Contains(audience))
            {
                return false; // Audience mismatch
            }

            // Validate nonce (required)
            if (!payload.TryGetProperty("nonce", out var nonceElement) ||
                nonceElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var nonceClaim = nonceElement.GetString();
            if (string.IsNullOrWhiteSpace(nonceClaim) ||
                !string.Equals(nonceClaim, expectedNonce, StringComparison.Ordinal))
            {
                return false;
            }

            // Validate iat (issued at) claim for freshness - REQUIRED by spec section 4.3.3
            // "The Verifier MUST check that the creation time of the Key Binding JWT,
            // as determined by the iat claim, is within an acceptable window."
            if (!payload.TryGetProperty("iat", out var iatElement) ||
                iatElement.ValueKind != JsonValueKind.Number ||
                !iatElement.TryGetInt64(out var iatUnixSeconds))
            {
                return false; // Invalid iat format
            }

            DateTimeOffset iat;
            try
            {
                iat = DateTimeOffset.FromUnixTimeSeconds(iatUnixSeconds);
            }
            catch (ArgumentOutOfRangeException)
            {
                return false; // Out-of-range numeric dates are invalid claims.
            }

            var now = _timeProvider.GetUtcNow();

            // Reject if KB-JWT is too old (replay attack prevention)
            var maxAge = TimeSpan.FromSeconds(Constants.MAX_KEY_BINDING_JWT_AGE_SECONDS);
            if (now - iat > maxAge)
            {
                return false; // KB-JWT is too old
            }

            // Reject if iat is in the future (with small tolerance for clock skew)
            var clockSkewTolerance = TimeSpan.FromSeconds(60); // 1 minute tolerance
            if (iat > now + clockSkewTolerance)
            {
                return false; // KB-JWT issued in the future
            }

            // Verify signature
            var signingInput = $"{headerBase64}.{payloadBase64}";
            var signature = Base64UrlEncoder.DecodeBytes(signatureBase64);

            using var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportSubjectPublicKeyInfo(holderPublicKey, out _);
            }
            catch (CryptographicException)
            {
                // Invalid key format
                return false;
            }

            // Validate elliptic curve - only P-256 (ES256) is supported
            if (!EcCurveGuard.IsP256(ecdsa))
            {
                return false; // Only P-256 curve is supported for ES256
            }

            return ecdsa.VerifyData(
                System.Text.Encoding.UTF8.GetBytes(signingInput),
                signature,
                HashAlgorithmName.SHA256
            );
        }
        catch (CryptographicException)
        {
            // Cryptographic operation failed
            return false;
        }
        catch (FormatException)
        {
            // Base64 decoding failed
            return false;
        }
        catch (JsonException)
        {
            // JSON parsing failed
            return false;
        }
        catch (SdJwtException)
        {
            // Base64UrlEncoder.DecodeBytes/DecodeString throws SdJwtException on invalid input
            return false;
        }
    }
}
