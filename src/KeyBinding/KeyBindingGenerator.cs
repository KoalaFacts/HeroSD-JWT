using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSdJwt.KeyBinding;

/// <summary>
/// Generates key binding JWTs for SD-JWT presentations.
/// Key binding proves the holder controls the private key referenced in the SD-JWT.
/// </summary>
public class KeyBindingGenerator
{
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

        // Create header with typ: "kb+jwt" and alg: "ES256"
        var header = new
        {
            alg = "ES256",
            typ = "kb+jwt"
        };

        // Create payload with required claims
        var payload = new
        {
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            aud = audience,
            nonce = nonce,
            sd_hash = sdJwtHash
        };

        // Encode header and payload
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);
        var headerBase64 = Base64UrlEncode(headerJson);
        var payloadBase64 = Base64UrlEncode(payloadJson);

        // Sign with holder's private key
        var signingInput = $"{headerBase64}.{payloadBase64}";
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(holderPrivateKey, out _);
        var signature = ecdsa.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256
        );

        var signatureBase64 = Base64UrlEncode(signature);
        return $"{signingInput}.{signatureBase64}";
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
