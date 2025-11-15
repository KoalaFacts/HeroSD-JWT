using HeroSdJwt.Encoding;
using HeroSdJwt.Internal.Ed25519;
using HeroSdJwt.Primitives;
using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Cryptography;

/// <summary>
/// Creates and signs JWTs using various signature algorithms.
/// Supports HS256, HS384, HS512, RS256, PS256, ES256, ES384, ES512, and EdDSA per RFC 7518.
/// </summary>
public class JwtSigner : IJwtSigner
{

    /// <summary>
    /// Creates a signed JWT with the specified payload and algorithm.
    /// </summary>
    /// <param name="payload">JWT payload claims.</param>
    /// <param name="signingKey">Signing key (format depends on algorithm).</param>
    /// <param name="algorithm">Signature algorithm to use.</param>
    /// <param name="keyId">Optional key identifier to include in JWT header (RFC 7515 'kid' parameter).</param>
    /// <returns>Signed JWT in format: header.payload.signature</returns>
    public string CreateJwt(
        Dictionary<string, object> payload,
        byte[] signingKey,
        SignatureAlgorithm algorithm,
        string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(signingKey);

        // Reject empty keys for security
        if (signingKey.Length == 0)
        {
            throw new ArgumentException("Signing key cannot be empty", nameof(signingKey));
        }

        // Create header with algorithm
        var algName = algorithm switch
        {
            SignatureAlgorithm.HS256 => "HS256",
            SignatureAlgorithm.RS256 => "RS256",
            SignatureAlgorithm.ES256 => "ES256",
            SignatureAlgorithm.EdDSA => "EdDSA",
            SignatureAlgorithm.HS384 => "HS384",
            SignatureAlgorithm.HS512 => "HS512",
            SignatureAlgorithm.PS256 => "PS256",
            SignatureAlgorithm.ES384 => "ES384",
            SignatureAlgorithm.ES512 => "ES512",
#if NET10_0_OR_GREATER
            SignatureAlgorithm.MLDSA65 => "MLDSA65",
            SignatureAlgorithm.MLDSA87 => "MLDSA87",
#endif
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}", nameof(algorithm))
        };

        var header = new Dictionary<string, object>
        {
            { "alg", algName },
            { "typ", "JWT" }
        };

        // Add key ID if provided (RFC 7515 Section 4.1.4)
        if (!string.IsNullOrWhiteSpace(keyId))
        {
            header["kid"] = keyId;
        }

        // Encode header and payload using AOT-compatible serialization
        var headerJson = SerializeDictionary(header);
        var headerBase64 = Base64UrlEncoder.Encode(headerJson);

        var payloadJson = SerializeDictionary(payload);
        var payloadBase64 = Base64UrlEncoder.Encode(payloadJson);

        // Create signing input
        var signingInput = $"{headerBase64}.{payloadBase64}";
        var signingInputBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);

        // Sign based on algorithm
        byte[] signatureBytes = algorithm switch
        {
            SignatureAlgorithm.HS256 => SignHmacSha256(signingInputBytes, signingKey),
            SignatureAlgorithm.RS256 => SignRsa256(signingInputBytes, signingKey),
            SignatureAlgorithm.ES256 => SignEcdsa256(signingInputBytes, signingKey),
            SignatureAlgorithm.EdDSA => SignEdDsa(signingInputBytes, signingKey),
            SignatureAlgorithm.HS384 => SignHmacSha384(signingInputBytes, signingKey),
            SignatureAlgorithm.HS512 => SignHmacSha512(signingInputBytes, signingKey),
            SignatureAlgorithm.PS256 => SignPss256(signingInputBytes, signingKey),
            SignatureAlgorithm.ES384 => SignEcdsa384(signingInputBytes, signingKey),
            SignatureAlgorithm.ES512 => SignEcdsa512(signingInputBytes, signingKey),
#if NET10_0_OR_GREATER
            SignatureAlgorithm.MLDSA65 => SignMlDsa65(signingInputBytes, signingKey),
            SignatureAlgorithm.MLDSA87 => SignMlDsa87(signingInputBytes, signingKey),
#endif
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

    /// <summary>
    /// Signs data using EdDSA with Ed25519 curve (asymmetric).
    /// Key must be a 64-byte expanded Ed25519 private key.
    /// </summary>
    private static byte[] SignEdDsa(byte[] data, byte[] privateKeyBytes)
    {
        if (privateKeyBytes.Length != 64)
        {
            throw new ArgumentException(
                $"Ed25519 private key must be 64 bytes (expanded format). Provided key is {privateKeyBytes.Length} bytes.",
                nameof(privateKeyBytes));
        }

        var signature = new byte[64];
        Ed25519Operations.CryptoSign(signature, 0, data, 0, data.Length, privateKeyBytes, 0);
        return signature;
    }


    /// <summary>
    /// Signs data using HMAC-SHA384 (symmetric).
    /// </summary>
    private static byte[] SignHmacSha384(byte[] data, byte[] key)
    {
        return HMACSHA384.HashData(key, data);
    }

    /// <summary>
    /// Signs data using HMAC-SHA512 (symmetric).
    /// </summary>
    private static byte[] SignHmacSha512(byte[] data, byte[] key)
    {
        return HMACSHA512.HashData(key, data);
    }

    /// <summary>
    /// Signs data using RSA-SHA256 with PSS padding (asymmetric).
    /// Key must be in PKCS#8 PrivateKeyInfo format.
    /// </summary>
    private static byte[] SignPss256(byte[] data, byte[] privateKeyBytes)
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

            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
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
    /// Signs data using ECDSA-SHA384 with P-384 curve (asymmetric).
    /// Key must be in PKCS#8 PrivateKeyInfo format with P-384 curve.
    /// </summary>
    private static byte[] SignEcdsa384(byte[] data, byte[] privateKeyBytes)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            // Validate curve is P-384 (secp384r1) as required for ES384
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Curve.Oid?.Value != "1.3.132.0.34") // P-384 OID
            {
                throw new ArgumentException(
                    "ES384 requires P-384 (secp384r1) curve. Provided key uses a different curve.",
                    nameof(privateKeyBytes));
            }

            return ecdsa.SignData(data, HashAlgorithmName.SHA384);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException(
                "Invalid ECDSA private key format. Expected PKCS#8 PrivateKeyInfo format with P-384 curve.",
                nameof(privateKeyBytes),
                ex);
        }
    }

    /// <summary>
    /// Signs data using ECDSA-SHA512 with P-521 curve (asymmetric).
    /// Key must be in PKCS#8 PrivateKeyInfo format with P-521 curve.
    /// </summary>
    private static byte[] SignEcdsa512(byte[] data, byte[] privateKeyBytes)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            // Validate curve is P-521 (secp521r1) as required for ES512
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Curve.Oid?.Value != "1.3.132.0.35") // P-521 OID
            {
                throw new ArgumentException(
                    "ES512 requires P-521 (secp521r1) curve. Provided key uses a different curve.",
                    nameof(privateKeyBytes));
            }

            return ecdsa.SignData(data, HashAlgorithmName.SHA512);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException(
                "Invalid ECDSA private key format. Expected PKCS#8 PrivateKeyInfo format with P-521 curve.",
                nameof(privateKeyBytes),
                ex);
        }
    }

    /// <summary>
    /// Serializes a dictionary to JSON using Utf8JsonWriter for AOT compatibility.
    /// Handles string, number, boolean, and JsonElement values.
    /// </summary>
    private static string SerializeDictionary(Dictionary<string, object> dict)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();

            foreach (var kvp in dict)
            {
                writer.WritePropertyName(kvp.Key);
                WriteValue(writer, kvp.Value);
            }

            writer.WriteEndObject();
            writer.Flush();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>
    /// Writes a value of unknown type to Utf8JsonWriter.
    /// Supports primitives, JsonElement, dictionaries, and collections for AOT compatibility.
    /// </summary>
    private static void WriteValue(Utf8JsonWriter writer, object value)
    {
        switch (value)
        {
            case string s:
                writer.WriteStringValue(s);
                break;
            case int i:
                writer.WriteNumberValue(i);
                break;
            case long l:
                writer.WriteNumberValue(l);
                break;
            case double d:
                writer.WriteNumberValue(d);
                break;
            case float f:
                writer.WriteNumberValue(f);
                break;
            case decimal dec:
                writer.WriteNumberValue(dec);
                break;
            case bool b:
                writer.WriteBooleanValue(b);
                break;
            case JsonElement je:
                je.WriteTo(writer);
                break;
            case null:
                writer.WriteNullValue();
                break;
            case Dictionary<string, object> nestedDict:
                writer.WriteStartObject();
                foreach (var kvp in nestedDict)
                {
                    writer.WritePropertyName(kvp.Key);
                    WriteValue(writer, kvp.Value);
                }
                writer.WriteEndObject();
                break;
            case Dictionary<string, string> stringDict:
                writer.WriteStartObject();
                foreach (var kvp in stringDict)
                {
                    writer.WritePropertyName(kvp.Key);
                    writer.WriteStringValue(kvp.Value);
                }
                writer.WriteEndObject();
                break;
            case System.Collections.IEnumerable enumerable when value is not string:
                writer.WriteStartArray();
                foreach (var item in enumerable)
                {
                    WriteValue(writer, item);
                }
                writer.WriteEndArray();
                break;
            case Models.Digest digest:
                // Digest objects are serialized as simple strings
                writer.WriteStartObject();
                writer.WriteString("...", digest.Value);
                writer.WriteEndObject();
                break;
            default:
                // For any other type, fall back to JsonSerializer.SerializeToElement
                // Suppression: Fallback for edge cases at API boundary (rarely hit).
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement fallback
                var element = JsonSerializer.SerializeToElement(value);
#pragma warning restore IL2026, IL3050
                element.WriteTo(writer);
                break;
        }
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Signs data using ML-DSA-65 post-quantum digital signature algorithm.
    /// Key must be in binary format per FIPS 204.
    /// </summary>
    /// <param name="data">Data to sign.</param>
    /// <param name="privateKeyBytes">ML-DSA-65 private key (~2,560 bytes).</param>
    /// <returns>ML-DSA-65 signature (~3,309 bytes).</returns>
    private static byte[] SignMlDsa65(byte[] data, byte[] privateKeyBytes)
    {
        // Note: This is a placeholder for the actual .NET 10 API
        // The actual implementation will use System.Security.Cryptography ML-DSA APIs
        // when .NET 10 is released with PQC support

        throw new NotImplementedException(
            "ML-DSA-65 signing requires .NET 10 with PQC support. " +
            "This is a preview implementation pending .NET 10 GA release.");

        // Expected implementation (when .NET 10 PQC APIs are available):
        // try
        // {
        //     using var mlDsa = MLDsa65.Create();
        //     mlDsa.ImportPrivateKey(privateKeyBytes);
        //     return mlDsa.SignData(data);
        // }
        // catch (CryptographicException ex)
        // {
        //     throw new ArgumentException(
        //         "Invalid ML-DSA-65 private key format. Expected binary format per FIPS 204.",
        //         nameof(privateKeyBytes),
        //         ex);
        // }
    }

    /// <summary>
    /// Signs data using ML-DSA-87 post-quantum digital signature algorithm.
    /// Key must be in binary format per FIPS 204.
    /// </summary>
    /// <param name="data">Data to sign.</param>
    /// <param name="privateKeyBytes">ML-DSA-87 private key (~4,896 bytes).</param>
    /// <returns>ML-DSA-87 signature (~4,627 bytes).</returns>
    private static byte[] SignMlDsa87(byte[] data, byte[] privateKeyBytes)
    {
        // Note: This is a placeholder for the actual .NET 10 API
        // The actual implementation will use System.Security.Cryptography ML-DSA APIs
        // when .NET 10 is released with PQC support

        throw new NotImplementedException(
            "ML-DSA-87 signing requires .NET 10 with PQC support. " +
            "This is a preview implementation pending .NET 10 GA release.");

        // Expected implementation (when .NET 10 PQC APIs are available):
        // try
        // {
        //     using var mlDsa = MLDsa87.Create();
        //     mlDsa.ImportPrivateKey(privateKeyBytes);
        //     return mlDsa.SignData(data);
        // }
        // catch (CryptographicException ex)
        // {
        //     throw new ArgumentException(
        //         "Invalid ML-DSA-87 private key format. Expected binary format per FIPS 204.",
        //         nameof(privateKeyBytes),
        //         ex);
        // }
    }
#endif
}
