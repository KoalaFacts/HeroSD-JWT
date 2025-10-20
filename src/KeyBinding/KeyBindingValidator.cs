using HeroSdJwt.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Validates key binding JWTs to prove holder possession of private key.
/// </summary>
internal static class KeyBindingValidator
{
    /// <summary>
    /// Validates a key binding JWT against the holder's public key.
    /// </summary>
    /// <param name="keyBindingJwt">The key binding JWT to validate.</param>
    /// <param name="holderPublicKey">The holder's public key from the cnf claim.</param>
    /// <param name="expectedSdJwtHash">The expected SD-JWT hash.</param>
    /// <param name="expectedAudience">The expected audience.</param>
    /// <param name="expectedNonce">The expected nonce.</param>
    /// <returns>True if valid; otherwise, false.</returns>
    public static bool ValidateKeyBinding(
        string keyBindingJwt,
        byte[] holderPublicKey,
        string expectedSdJwtHash,
        string? expectedAudience = null,
        string? expectedNonce = null)
    {
        ArgumentNullException.ThrowIfNull(keyBindingJwt);
        ArgumentNullException.ThrowIfNull(holderPublicKey);
        ArgumentNullException.ThrowIfNull(expectedSdJwtHash);

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
            var headerJson = DecodeBase64Url(headerBase64);
            var header = JsonDocument.Parse(headerJson).RootElement;

            if (!header.TryGetProperty("typ", out var typElement) ||
                typElement.GetString() != "kb+jwt")
            {
                return false;
            }

            // Decode and validate payload
            var payloadJson = DecodeBase64Url(payloadBase64);
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

            // Validate audience if provided
            if (expectedAudience != null)
            {
                if (!payload.TryGetProperty("aud", out var audElement) ||
                    audElement.GetString() != expectedAudience)
                {
                    return false;
                }
            }

            // Validate nonce if provided
            if (expectedNonce != null)
            {
                if (!payload.TryGetProperty("nonce", out var nonceElement) ||
                    nonceElement.GetString() != expectedNonce)
                {
                    return false;
                }
            }

            // Verify signature
            var signingInput = $"{headerBase64}.{payloadBase64}";
            var signature = Convert.FromBase64String(
                signatureBase64.Replace('-', '+').Replace('_', '/')
                    .PadRight(signatureBase64.Length + (4 - signatureBase64.Length % 4) % 4, '='));

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
                Encoding.UTF8.GetBytes(signingInput),
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
    }

    private static string DecodeBase64Url(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/')
            .PadRight(base64Url.Length + (4 - base64Url.Length % 4) % 4, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
    }
}
