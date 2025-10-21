using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSdJwt.Common;

/// <summary>
/// Creates and signs JWTs using various signature algorithms.
/// Supports HS256, RS256, and ES256 per RFC 7518.
/// </summary>
internal static class JwtSigner
{
    /// <summary>
    /// Creates a signed JWT with the specified payload and algorithm.
    /// </summary>
    /// <param name="payload">JWT payload claims.</param>
    /// <param name="signingKey">Signing key (format depends on algorithm).</param>
    /// <param name="algorithm">Signature algorithm to use.</param>
    /// <returns>Signed JWT in format: header.payload.signature</returns>
    public static string CreateJwt(
        Dictionary<string, object> payload,
        byte[] signingKey,
        SignatureAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(signingKey);

        // Create header with algorithm
        var algName = algorithm switch
        {
            SignatureAlgorithm.HS256 => "HS256",
            SignatureAlgorithm.RS256 => "RS256",
            SignatureAlgorithm.ES256 => "ES256",
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}", nameof(algorithm))
        };

        var header = new Dictionary<string, object>
        {
            { "alg", algName },
            { "typ", "JWT" }
        };

        // Encode header and payload
        var headerJson = JsonSerializer.Serialize(header);
        var headerBase64 = Base64UrlEncoder.Encode(headerJson);

        var payloadJson = JsonSerializer.Serialize(payload);
        var payloadBase64 = Base64UrlEncoder.Encode(payloadJson);

        // Create signing input
        var signingInput = $"{headerBase64}.{payloadBase64}";
        var signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

        // Sign based on algorithm
        byte[] signatureBytes = algorithm switch
        {
            SignatureAlgorithm.HS256 => SignHmacSha256(signingInputBytes, signingKey),
            SignatureAlgorithm.RS256 => SignRsa256(signingInputBytes, signingKey),
            SignatureAlgorithm.ES256 => SignEcdsa256(signingInputBytes, signingKey),
            _ => throw new ArgumentException($"Algorithm {algorithm} not implemented", nameof(algorithm))
        };

        var signatureBase64 = Base64UrlEncoder.Encode(signatureBytes);

        return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
    }

    /// <summary>
    /// Signs data using HMAC-SHA256 (symmetric).
    /// </summary>
    private static byte[] SignHmacSha256(byte[] data, byte[] key)
    {
        return HMACSHA256.HashData(key, data);
    }

    /// <summary>
    /// Signs data using RSA-SHA256 with PKCS#1 v1.5 padding (asymmetric).
    /// Key must be in PKCS#8 PrivateKeyInfo format.
    /// </summary>
    private static byte[] SignRsa256(byte[] data, byte[] privateKeyBytes)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            // Validate minimum key size (2048 bits per NIST recommendations)
            const int MinimumRsaKeySize = 2048;
            if (rsa.KeySize < MinimumRsaKeySize)
            {
                throw new ArgumentException(
                    $"RSA key size {rsa.KeySize} is below minimum required size of {MinimumRsaKeySize} bits",
                    nameof(privateKeyBytes));
            }

            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException(
                "Invalid RSA private key format. Expected PKCS#8 PrivateKeyInfo format.",
                nameof(privateKeyBytes),
                ex);
        }
    }

    /// <summary>
    /// Signs data using ECDSA-SHA256 with P-256 curve (asymmetric).
    /// Key must be in PKCS#8 PrivateKeyInfo format with P-256 curve.
    /// </summary>
    private static byte[] SignEcdsa256(byte[] data, byte[] privateKeyBytes)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            // Validate curve is P-256 (secp256r1) as required for ES256
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Curve.Oid?.Value != "1.2.840.10045.3.1.7") // P-256 OID
            {
                throw new ArgumentException(
                    "ES256 requires P-256 (secp256r1) curve. Provided key uses a different curve.",
                    nameof(privateKeyBytes));
            }

            return ecdsa.SignData(data, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException(
                "Invalid ECDSA private key format. Expected PKCS#8 PrivateKeyInfo format with P-256 curve.",
                nameof(privateKeyBytes),
                ex);
        }
    }
}
