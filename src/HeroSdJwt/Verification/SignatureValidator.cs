using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Internal.Ed25519;
using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Text.Json;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;

namespace HeroSdJwt.Verification;

/// <summary>
/// Validates JWT signatures using cryptographic verification.
/// </summary>
public class SignatureValidator : ISignatureValidator
{

    /// <summary>
    /// Verifies the signature of a JWT.
    /// </summary>
    /// <param name="jwt">The JWT in format: header.payload.signature</param>
    /// <param name="publicKey">The public key or shared secret for verification.</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when jwt or publicKey is null.</exception>
    /// <exception cref="AlgorithmConfusionException">Thrown when algorithm is "none" or case variant.</exception>
    /// <exception cref="AlgorithmNotSupportedException">Thrown when algorithm is not supported.</exception>
    /// <exception cref="SdJwtException">Thrown when JWT format is invalid.</exception>
    public bool VerifyJwtSignature(string jwt, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(publicKey);

        // Parse JWT into header, payload, signature
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new SdJwtException(
                "Invalid JWT format: expected 3 parts separated by dots",
                ErrorCode.InvalidInput);
        }

        var headerBase64 = parts[0];
        var payloadBase64 = parts[1];
        var signatureBase64 = parts[2];

        // Decode and parse header
        var headerJson = Base64UrlEncoder.DecodeString(headerBase64);
        var header = JsonDocument.Parse(headerJson).RootElement;

        // Extract algorithm
        if (!header.TryGetProperty("alg", out var algElement))
        {
            throw new SdJwtException(
                "JWT header missing required 'alg' claim",
                ErrorCode.InvalidInput);
        }

        var algorithm = algElement.GetString();
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            throw new SdJwtException(
                "JWT 'alg' claim cannot be empty",
                ErrorCode.InvalidInput);
        }

        // Check for "none" algorithm (case-insensitive) - algorithm confusion attack
        if (algorithm.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            throw new AlgorithmConfusionException(
                "The 'none' algorithm is not allowed for security reasons");
        }

        // Verify algorithm is supported
        if (!IsSupportedAlgorithm(algorithm))
        {
#if NET10_0_OR_GREATER
            throw new AlgorithmNotSupportedException(
                $"Algorithm '{algorithm}' is not supported. Supported algorithms: HS256, HS384, HS512, RS256, PS256, ES256, ES384, ES512, EdDSA");
#else
            throw new AlgorithmNotSupportedException(
                $"Algorithm '{algorithm}' is not supported. Supported algorithms: HS256, HS384, HS512, RS256, PS256, ES256, ES384, ES512, EdDSA");
#endif
        }

        // Construct the signing input (header.payload)
        var signingInput = $"{headerBase64}.{payloadBase64}";
        var signingInputBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);

        // Decode signature
        var signatureBytes = Base64UrlEncoder.DecodeBytes(signatureBase64);

        // Verify signature based on algorithm
        return algorithm switch
        {
            "HS256" => VerifyHmacSha256(signingInputBytes, signatureBytes, publicKey),
            "HS384" => VerifyHmacSha384(signingInputBytes, signatureBytes, publicKey),
            "HS512" => VerifyHmacSha512(signingInputBytes, signatureBytes, publicKey),
            "RS256" => VerifyRsa256(signingInputBytes, signatureBytes, publicKey),
            "PS256" => VerifyPss256(signingInputBytes, signatureBytes, publicKey),
            "ES256" => VerifyEcdsa256(signingInputBytes, signatureBytes, publicKey),
            "ES384" => VerifyEcdsa384(signingInputBytes, signatureBytes, publicKey),
            "ES512" => VerifyEcdsa512(signingInputBytes, signatureBytes, publicKey),
            "EdDSA" => VerifyEdDsa(signingInputBytes, signatureBytes, publicKey),
#if NET10_0_OR_GREATER
            "MLDSA65" => VerifyMlDsa65(signingInputBytes, signatureBytes, publicKey),
            "MLDSA87" => VerifyMlDsa87(signingInputBytes, signatureBytes, publicKey),
#endif
            _ => throw new AlgorithmNotSupportedException($"Algorithm '{algorithm}' verification not implemented")
        };
    }

    /// <summary>
    /// Verifies an HMAC-SHA256 signature using constant-time comparison.
    /// </summary>
    private static bool VerifyHmacSha256(byte[] data, byte[] signature, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        var computedSignature = hmac.ComputeHash(data);

        // Use constant-time comparison to prevent timing attacks
        return CryptographicOperations.FixedTimeEquals(computedSignature, signature);
    }


    /// <summary>
    /// Verifies an HMAC-SHA384 signature using constant-time comparison.
    /// </summary>
    private static bool VerifyHmacSha384(byte[] data, byte[] signature, byte[] key)
    {
        using var hmac = new HMACSHA384(key);
        var computedSignature = hmac.ComputeHash(data);

        // Use constant-time comparison to prevent timing attacks
        return CryptographicOperations.FixedTimeEquals(computedSignature, signature);
    }

    /// <summary>
    /// Verifies an HMAC-SHA512 signature using constant-time comparison.
    /// </summary>
    private static bool VerifyHmacSha512(byte[] data, byte[] signature, byte[] key)
    {
        using var hmac = new HMACSHA512(key);
        var computedSignature = hmac.ComputeHash(data);

        // Use constant-time comparison to prevent timing attacks
        return CryptographicOperations.FixedTimeEquals(computedSignature, signature);
    }

    /// <summary>
    /// Verifies an RSA-SHA256 signature.
    /// Requires minimum 2048-bit RSA keys for security.
    /// </summary>
    private static bool VerifyRsa256(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            // Validate minimum key size (2048 bits per NIST recommendations)
            const int MinimumRsaKeySize = 2048;
            if (rsa.KeySize < MinimumRsaKeySize)
            {
                throw new SdJwtException(
                    $"RSA key size {rsa.KeySize} is below minimum required size of {MinimumRsaKeySize} bits",
                    ErrorCode.InvalidInput);
            }

            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (SdJwtException)
        {
            throw; // Re-throw our validation exceptions
        }
        catch (CryptographicException)
        {
            // Signature verification failed - legitimate cryptographic failure
            return false;
        }
        catch (ArgumentException)
        {
            // Invalid key format
            return false;
        }
        catch
        {
            // Other unexpected errors - fail safely
            return false;
        }
    }

    /// <summary>
    /// Verifies an RSA-PSS signature with SHA-256.
    /// Requires minimum 2048-bit RSA keys for security.
    /// </summary>
    private static bool VerifyPss256(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            // Validate minimum key size (2048 bits per NIST recommendations)
            const int MinimumRsaKeySize = 2048;
            if (rsa.KeySize < MinimumRsaKeySize)
            {
                throw new SdJwtException(
                    $"RSA key size {rsa.KeySize} is below minimum required size of {MinimumRsaKeySize} bits",
                    ErrorCode.InvalidInput);
            }

            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (SdJwtException)
        {
            throw; // Re-throw our validation exceptions
        }
        catch (CryptographicException)
        {
            // Signature verification failed - legitimate cryptographic failure
            return false;
        }
        catch (ArgumentException)
        {
            // Invalid key format
            return false;
        }
        catch
        {
            // Other unexpected errors - fail safely
            return false;
        }
    }

    /// <summary>
    /// Verifies an ECDSA-SHA256 signature.
    /// Validates that the curve is P-256 (secp256r1) as required for ES256.
    /// </summary>
    private static bool VerifyEcdsa256(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            // Validate curve parameters for ES256 (must be P-256/secp256r1)
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Curve.Oid?.Value != "1.2.840.10045.3.1.7") // P-256 OID
            {
                throw new SdJwtException(
                    "ES256 requires P-256 (secp256r1) curve",
                    ErrorCode.InvalidInput);
            }

            if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256))
            {
                return true;
            }

            ReadOnlySpan<byte> signatureToTry = signature;
            if (signature.Length == 32 * 2 && (signature.Length == 0 || signature[0] != 0x30))
            {
                signatureToTry = ConvertJoseToDerSignature(signature, coordinateSize: 32);
            }

            var hash = SHA256.HashData(data);
            return ecdsa.VerifyHash(hash, signatureToTry);
        }
        catch (SdJwtException)
        {
            throw; // Re-throw our validation exceptions
        }
        catch (CryptographicException)
        {
            // Signature verification failed - legitimate cryptographic failure
            return false;
        }
        catch (ArgumentException)
        {
            // Invalid key format
            return false;
        }
        catch
        {
            // Other unexpected errors - fail safely
            return false;
        }
    }

    /// <summary>
    /// Verifies an ECDSA-SHA384 signature.
    /// Validates that the curve is P-384 (secp384r1) as required for ES384.
    /// </summary>
    private static bool VerifyEcdsa384(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            // Validate curve parameters for ES384 (must be P-384/secp384r1)
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Curve.Oid?.Value != "1.3.132.0.34") // P-384 OID
            {
                throw new SdJwtException(
                    "ES384 requires P-384 (secp384r1) curve",
                    ErrorCode.InvalidInput);
            }

            if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA384))
            {
                return true;
            }

            ReadOnlySpan<byte> signatureToTry = signature;
            if (signature.Length == 48 * 2 && (signature.Length == 0 || signature[0] != 0x30))
            {
                signatureToTry = ConvertJoseToDerSignature(signature, coordinateSize: 48);
            }

            var hash = SHA384.HashData(data);
            return ecdsa.VerifyHash(hash, signatureToTry);
        }
        catch (SdJwtException)
        {
            throw; // Re-throw our validation exceptions
        }
        catch (CryptographicException)
        {
            // Signature verification failed - legitimate cryptographic failure
            return false;
        }
        catch (ArgumentException)
        {
            // Invalid key format
            return false;
        }
        catch
        {
            // Other unexpected errors - fail safely
            return false;
        }
    }

    /// <summary>
    /// Verifies an ECDSA-SHA512 signature.
    /// Validates that the curve is P-521 (secp521r1) as required for ES512.
    /// </summary>
    private static bool VerifyEcdsa512(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            // Validate curve parameters for ES512 (must be P-521/secp521r1)
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Curve.Oid?.Value != "1.3.132.0.35") // P-521 OID
            {
                throw new SdJwtException(
                    "ES512 requires P-521 (secp521r1) curve",
                    ErrorCode.InvalidInput);
            }

            if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA512))
            {
                return true;
            }

            ReadOnlySpan<byte> signatureToTry = signature;
            if (signature.Length == 66 * 2 && (signature.Length == 0 || signature[0] != 0x30))
            {
                signatureToTry = ConvertJoseToDerSignature(signature, coordinateSize: 66); // P-521 coordinate size in bytes
            }

            var hash = SHA512.HashData(data);
            return ecdsa.VerifyHash(hash, signatureToTry);
        }
        catch (SdJwtException)
        {
            throw; // Re-throw our validation exceptions
        }
        catch (CryptographicException)
        {
            // Signature verification failed - legitimate cryptographic failure
            return false;
        }
        catch (ArgumentException)
        {
            // Invalid key format
            return false;
        }
        catch
        {
            // Other unexpected errors - fail safely
            return false;
        }
    }

    /// <summary>
    /// Verifies the signature of a JWT using key resolution.
    /// Extracts the 'kid' (key ID) from JWT header and uses the resolver to obtain the verification key.
    /// </summary>
    /// <param name="jwt">The JWT in format: header.payload.signature</param>
    /// <param name="keyResolver">Delegate to resolve key IDs to verification keys. Called only if JWT contains 'kid'.</param>
    /// <param name="fallbackKey">Optional fallback key to use when JWT has no 'kid' parameter (backward compatibility).</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    /// <exception cref="SdJwtException">Thrown when JWT contains kid but resolver returns null (KeyIdNotFound), or when kid is present but no resolver/fallback provided (KeyResolverMissing), or when resolver throws an exception (KeyResolverFailed).</exception>
    public bool VerifyJwtSignature(string jwt, Primitives.KeyResolver? keyResolver, byte[]? fallbackKey = null)
    {
        ArgumentNullException.ThrowIfNull(jwt);

        // Parse JWT to extract header
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new SdJwtException(
                "Invalid JWT format: expected 3 parts separated by dots",
                ErrorCode.InvalidInput);
        }

        var headerBase64 = parts[0];

        // Decode and parse header
        var headerJson = Base64UrlEncoder.DecodeString(headerBase64);
        var header = JsonDocument.Parse(headerJson).RootElement;

        // Check if kid is present in header
        byte[] verificationKey;
        if (header.TryGetProperty("kid", out var kidElement) && kidElement.ValueKind == JsonValueKind.String)
        {
            var keyId = kidElement.GetString();

            if (string.IsNullOrWhiteSpace(keyId))
            {
                throw new SdJwtException(
                    "JWT header contains empty 'kid' claim",
                    ErrorCode.InvalidInput);
            }

            // Kid is present - must use resolver
            if (keyResolver == null)
            {
                throw new SdJwtException(
                    "JWT contains 'kid' parameter but no key resolver was provided",
                    ErrorCode.KeyResolverMissing);
            }

            // Resolve key ID to verification key
            try
            {
                verificationKey = keyResolver(keyId)!;

                if (verificationKey == null)
                {
                    throw new SdJwtException(
                        $"Key resolver could not find key for kid '{keyId}'",
                        ErrorCode.KeyIdNotFound);
                }
            }
            catch (SdJwtException)
            {
                throw; // Re-throw our exceptions
            }
            catch (Exception ex)
            {
                throw new SdJwtException(
                    $"Key resolver threw an exception while resolving kid '{keyId}': {ex.Message}",
                    ErrorCode.KeyResolverFailed,
                    ex);
            }
        }
        else
        {
            // No kid present - use fallback key
            if (fallbackKey == null)
            {
                throw new SdJwtException(
                    "JWT has no 'kid' parameter and no fallback key was provided",
                    ErrorCode.KeyResolverMissing);
            }

            verificationKey = fallbackKey;
        }

        // Verify signature using resolved/fallback key
        return VerifyJwtSignature(jwt, verificationKey);
    }

    /// <summary>
    /// Verifies an EdDSA signature using Ed25519.
    /// </summary>
    private static bool VerifyEdDsa(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        try
        {
            // Validate key size
            if (publicKeyBytes.Length != 32)
            {
                throw new SdJwtException(
                    $"Ed25519 public key must be 32 bytes. Provided key is {publicKeyBytes.Length} bytes.",
                    ErrorCode.InvalidInput);
            }

            // Validate signature size
            if (signature.Length != 64)
            {
                return false; // Invalid signature length
            }

            return Ed25519Operations.CryptoSignVerify(signature, 0, data, 0, data.Length, publicKeyBytes, 0);
        }
        catch (SdJwtException)
        {
            throw; // Re-throw our validation exceptions
        }
        catch
        {
            // Any other error - fail safely
            return false;
        }
    }

    /// <summary>
    /// Checks if an algorithm is supported for signature verification.
    /// </summary>
    private static bool IsSupportedAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            "HS256" => true,
            "HS384" => true,
            "HS512" => true,
            "RS256" => true,
            "PS256" => true,
            "ES256" => true,
            "ES384" => true,
            "ES512" => true,
            "EdDSA" => true,
            _ => false
        };
    }

    /// <summary>
    /// Converts a JOSE (R||S) ECDSA signature into DER format expected by ECDsa.VerifyData.
    /// Accepts raw R||S; if already DER, returns the input.
    /// </summary>
    private static byte[] ConvertJoseToDerSignature(ReadOnlySpan<byte> joseSignature, int coordinateSize)
    {
        // If this is already DER (starts with SEQUENCE tag), return as-is
        if (joseSignature.Length > 0 && joseSignature[0] == 0x30)
        {
            return joseSignature.ToArray();
        }

        if (joseSignature.Length != coordinateSize * 2)
        {
            throw new SdJwtException("Invalid ECDSA signature length.", ErrorCode.InvalidInput);
        }

        var r = joseSignature[..coordinateSize];
        var s = joseSignature[coordinateSize..];

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        WriteInteger(writer, r);
        WriteInteger(writer, s);
        writer.PopSequence();
        return writer.Encode();
    }

    private static void WriteInteger(AsnWriter writer, ReadOnlySpan<byte> value)
    {
        int offset = 0;
        while (offset < value.Length && value[offset] == 0x00)
        {
            offset++;
        }

        var trimmed = value[offset..];

        // Ensure positive integer by prefixing 0x00 when needed
        if (trimmed.Length == 0 || (trimmed[0] & 0x80) != 0)
        {
            Span<byte> padded = stackalloc byte[trimmed.Length + 1];
            trimmed.CopyTo(padded[1..]);
            writer.WriteInteger(padded);
        }
        else
        {
            writer.WriteInteger(trimmed);
        }
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Verifies an ML-DSA-65 post-quantum digital signature.
    /// Public key must be in binary format per FIPS 204.
    /// </summary>
    /// <param name="data">Data that was signed.</param>
    /// <param name="signature">ML-DSA-65 signature (~3,309 bytes).</param>
    /// <param name="publicKeyBytes">ML-DSA-65 public key (~1,952 bytes).</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    private static bool VerifyMlDsa65(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        // Placeholder for HeroCrypt integration once available
        throw new NotSupportedException(
            "ML-DSA-65 verification requires the HeroCrypt PQC package (pending release).");

        // Expected implementation (when .NET 10 PQC APIs are available):
        // try
        // {
        //     using var mlDsa = MLDsa65.Create();
        //     mlDsa.ImportPublicKey(publicKeyBytes);
        //     return mlDsa.VerifyData(data, signature);
        // }
        // catch (CryptographicException)
        // {
        //     // Invalid key format or verification failure
        //     return false;
        // }
    }

    /// <summary>
    /// Verifies an ML-DSA-87 post-quantum digital signature.
    /// Public key must be in binary format per FIPS 204.
    /// </summary>
    /// <param name="data">Data that was signed.</param>
    /// <param name="signature">ML-DSA-87 signature (~4,627 bytes).</param>
    /// <param name="publicKeyBytes">ML-DSA-87 public key (~2,592 bytes).</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    private static bool VerifyMlDsa87(byte[] data, byte[] signature, byte[] publicKeyBytes)
    {
        // Placeholder for HeroCrypt integration once available
        throw new NotSupportedException(
            "ML-DSA-87 verification requires the HeroCrypt PQC package (pending release).");

        // Expected implementation (when .NET 10 PQC APIs are available):
        // try
        // {
        //     using var mlDsa = MLDsa87.Create();
        //     mlDsa.ImportPublicKey(publicKeyBytes);
        //     return mlDsa.VerifyData(data, signature);
        // }
        // catch (CryptographicException)
        // {
        //     // Invalid key format or verification failure
        //     return false;
        // }
    }
#endif

}
