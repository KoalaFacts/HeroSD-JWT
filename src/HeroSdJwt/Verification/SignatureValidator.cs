using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
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
            throw new AlgorithmNotSupportedException(
                $"Algorithm '{algorithm}' is not supported. Supported algorithms: HS256, RS256, ES256");
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
            "RS256" => VerifyRsa256(signingInputBytes, signatureBytes, publicKey),
            "ES256" => VerifyEcdsa256(signingInputBytes, signatureBytes, publicKey),
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

            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
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
    /// Checks if an algorithm is supported for signature verification.
    /// </summary>
    private static bool IsSupportedAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            "HS256" => true,
            "RS256" => true,
            "ES256" => true,
            _ => false
        };
    }
}
