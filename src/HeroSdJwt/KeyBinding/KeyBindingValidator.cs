using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using System.Collections.Generic;
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
            : new[] { expectedAudience };

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

        if (expectedAudiences.Count == 0)
        {
            return false; // Spec requires audience binding
        }

        var expectedAudienceSet = new HashSet<string>(StringComparer.Ordinal);
        foreach (var audience in expectedAudiences)
        {
            if (!string.IsNullOrWhiteSpace(audience))
            {
                expectedAudienceSet.Add(audience);
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
            var header = JsonDocument.Parse(headerJson).RootElement;

            if (!header.TryGetProperty("typ", out var typElement) ||
                typElement.GetString() != "kb+jwt")
            {
                return false;
            }

            // Decode and validate payload
            var payloadJson = Base64UrlEncoder.DecodeString(payloadBase64);
            var payload = JsonDocument.Parse(payloadJson).RootElement;

            // Validate sd_hash claim exists and matches expected value
            if (!payload.TryGetProperty("sd_hash", out var sdHashElement))
            {
                return false;
            }

            var sdHashClaim = sdHashElement.GetString();
            if (sdHashClaim != expectedSdJwtHash)
            {
                return false; // SD-JWT hash mismatch
            }

            // Validate audience (required)
            if (!payload.TryGetProperty("aud", out var audElement))
            {
                return false;
            }

            bool audienceMatches = false;
            if (audElement.ValueKind == JsonValueKind.String)
            {
                if (audElement.GetString() is { Length: > 0 } audClaim &&
                    expectedAudienceSet.Contains(audClaim))
                {
                    audienceMatches = true;
                }
            }
            else if (audElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in audElement.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String &&
                        item.GetString() is { Length: > 0 } audClaim &&
                        expectedAudienceSet.Contains(audClaim))
                    {
                        audienceMatches = true;
                        break;
                    }
                }
            }
            else
            {
                return false; // Unsupported audience format
            }

            if (!audienceMatches)
            {
                return false; // Audience mismatch
            }

            // Validate nonce (required)
            if (!payload.TryGetProperty("nonce", out var nonceElement))
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
            if (!payload.TryGetProperty("iat", out var iatElement))
            {
                return false; // iat claim is required
            }

            if (!iatElement.TryGetInt64(out var iatUnixSeconds))
            {
                return false; // Invalid iat format
            }

            var iat = DateTimeOffset.FromUnixTimeSeconds(iatUnixSeconds);
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
            if (ecdsa.KeySize != 256)
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
