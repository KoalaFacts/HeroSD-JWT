using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
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

        // A caller-supplied blank expected hash provides no binding to the
        // presented SD-JWT, even if a correctly signed KB-JWT repeats it.
        if (string.IsNullOrWhiteSpace(expectedSdJwtHash))
        {
            return false;
        }

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
            // Discover exactly two JWT separators without Split. On .NET 8
            // even a count-limited Split first collects every delimiter index,
            // allowing a 64-KiB separator flood to allocate a large buffer.
            var firstSeparator = keyBindingJwt.IndexOf('.');
            if (firstSeparator <= 0)
            {
                return false;
            }

            var secondSeparator = keyBindingJwt.IndexOf('.', firstSeparator + 1);
            if (secondSeparator <= firstSeparator + 1 ||
                secondSeparator == keyBindingJwt.Length - 1 ||
                keyBindingJwt.IndexOf('.', secondSeparator + 1) >= 0)
            {
                return false;
            }

            var headerBase64 = keyBindingJwt[..firstSeparator];
            var payloadBase64 = keyBindingJwt[(firstSeparator + 1)..secondSeparator];
            var signatureBase64 = keyBindingJwt[(secondSeparator + 1)..];

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

            // Apply the same registered JOSE header type and critical-extension
            // checks as issuer-token verification before accepting a holder proof.
            if (JoseHeaderGuard.HasInvalidOrUnsupportedParameters(header))
            {
                return false;
            }

            // Authenticate the holder proof before parsing claims or consulting
            // the clock. An invalid signature must not consume application
            // services or cause errors from untrusted payload data.
            var signature = Base64UrlEncoder.DecodeBytes(signatureBase64);
            // ES256 uses exactly 64 bytes of JOSE R||S. Reject malformed
            // signatures before the more expensive public-key import.
            if (signature.Length != 64)
            {
                return false;
            }

            using var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportSubjectPublicKeyInfo(holderPublicKey, out var bytesRead);
                // The holder key must be exactly one SPKI object. Ignore no
                // trailing data, even when the SPKI prefix is otherwise valid.
                if (bytesRead != holderPublicKey.Length)
                {
                    return false;
                }
            }
            catch (CryptographicException)
            {
                return false; // Invalid key format
            }

            if (!EcCurveGuard.IsP256(ecdsa))
            {
                return false; // Only P-256 (ES256) is supported
            }

            // The compact protected header and payload are canonical
            // base64url (ASCII), validated by DecodeString above. Signatures
            // authenticate the exact header.payload bytes, including the dot.
            // Decode directly from the original input instead of allocating
            // both an interpolated string and a UTF-8 byte[] per verification.
            const int StackSigningInputLimit = 1024;
            Span<byte> signingInputBytes = secondSeparator <= StackSigningInputLimit
                ? stackalloc byte[secondSeparator]
                : new byte[secondSeparator];
            var byteCount = System.Text.Encoding.ASCII.GetBytes(
                keyBindingJwt.AsSpan(0, secondSeparator), signingInputBytes);

            if (!ecdsa.VerifyData(
                signingInputBytes[..byteCount],
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return false;
            }

            // Decode and validate payload
            var payloadJson = Base64UrlEncoder.DecodeString(payloadBase64);
            using var payloadDocument = JsonDocument.Parse(payloadJson);
            var payload = payloadDocument.RootElement;
            if (JsonObjectMemberGuard.HasInvalidOrDuplicateNames(payload))
            {
                // RFC 7519 requires unique claim names. A valid ES256 signature
                // cannot make ambiguous holder claims safe to consume.
                return false;
            }

            // RFC 9901 defines a KB-JWT as a JWT. RFC 7519 requires
            // registered iss, sub and jti claims to be strings when present.
            // Their shape is mandatory even without a separate matching policy.
            if ((payload.TryGetProperty("iss", out var issuer) &&
                 issuer.ValueKind != JsonValueKind.String) ||
                (payload.TryGetProperty("sub", out var subject) &&
                 subject.ValueKind != JsonValueKind.String) ||
                (payload.TryGetProperty("jti", out var jwtId) &&
                 jwtId.ValueKind != JsonValueKind.String))
            {
                return false;
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
                !NumericDateParser.TryParseUnixTicks(iatElement, out var iatTicks))
            {
                return false; // Invalid or out-of-range NumericDate.
            }

            var nowTicks = NumericDateParser.GetCurrentUnixTicks(_timeProvider.GetUtcNow());

            // Compare at the original precision, including sub-100ns fractions.
            // Rounding iat first would widen either the age or future-skew limit.
            var maxAgeTicks = Constants.MAX_KEY_BINDING_JWT_AGE_SECONDS * TimeSpan.TicksPerSecond;
            if (nowTicks - iatTicks > maxAgeTicks)
            {
                return false; // KB-JWT is too old
            }

            var clockSkewToleranceTicks = TimeSpan.FromSeconds(60).Ticks;
            if (iatTicks - nowTicks > clockSkewToleranceTicks)
            {
                return false; // KB-JWT issued in the future
            }

            // RFC 9901 defines KB-JWT as a JWT. Although exp and nbf are
            // optional here, RFC 7519 requires enforcing their validity
            // whenever the holder includes them. A fresh iat cannot override
            // an already expired or not-yet-valid signed holder proof.
            if (payload.TryGetProperty("exp", out var expElement) &&
                (!NumericDateParser.TryParseUnixTicks(expElement, out var expTicks) ||
                 nowTicks >= expTicks))
            {
                return false;
            }

            if (payload.TryGetProperty("nbf", out var nbfElement) &&
                (!NumericDateParser.TryParseUnixTicks(nbfElement, out var nbfTicks) ||
                 nowTicks < nbfTicks))
            {
                return false;
            }

            return true;
        }
        catch (CryptographicException)
        {
            // Cryptographic operation failed
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            // Some platforms reject an unsupported curve while importing its SPKI.
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
