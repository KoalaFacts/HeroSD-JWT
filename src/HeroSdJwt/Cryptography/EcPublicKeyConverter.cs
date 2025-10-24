using System.Security.Cryptography;
using System.Text.Json;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;

namespace HeroSdJwt.Cryptography;

/// <summary>
/// Converts between ECDSA public keys and JSON Web Key (JWK) format per RFC 7517.
/// Handles P-256 elliptic curve keys for SD-JWT key binding.
/// </summary>
internal class EcPublicKeyConverter : IEcPublicKeyConverter
{
    /// <summary>
    /// Converts an ECDSA public key to JWK (JSON Web Key) format.
    /// </summary>
    /// <param name="publicKeyBytes">The public key in SubjectPublicKeyInfo format.</param>
    /// <returns>A dictionary representing the JWK with kty, crv, x, y parameters.</returns>
    /// <exception cref="ArgumentException">If the key is invalid or not P-256.</exception>
    public Dictionary<string, object> ToJwk(byte[] publicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(publicKeyBytes);

        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid ECDSA public key format", nameof(publicKeyBytes), ex);
        }

        // Only P-256 is supported for ES256
        if (ecdsa.KeySize != 256)
        {
            throw new ArgumentException(
                $"Only P-256 (256-bit) elliptic curve is supported. Provided key is {ecdsa.KeySize}-bit.",
                nameof(publicKeyBytes));
        }

        // Export parameters to get x and y coordinates
        var parameters = ecdsa.ExportParameters(false);

        // Per RFC 7518 section 6.2.1, EC public key JWK contains:
        // - kty: Key Type (EC for Elliptic Curve)
        // - crv: Curve (P-256 for ES256)
        // - x: X coordinate (base64url encoded)
        // - y: Y coordinate (base64url encoded)
        return new Dictionary<string, object>
        {
            { "kty", "EC" },
            { "crv", "P-256" },
            { "x", Base64UrlEncoder.Encode(parameters.Q.X!) },
            { "y", Base64UrlEncoder.Encode(parameters.Q.Y!) }
        };
    }

    /// <summary>
    /// Converts a JWK (JSON Web Key) to ECDSA public key format.
    /// </summary>
    /// <param name="jwk">The JWK as a JsonElement.</param>
    /// <returns>The public key bytes in SubjectPublicKeyInfo format.</returns>
    /// <exception cref="ArgumentException">If the JWK is invalid or not P-256.</exception>
    public byte[] FromJwk(JsonElement jwk)
    {
        // Validate required fields
        if (!jwk.TryGetProperty("kty", out var ktyElement) || ktyElement.GetString() != "EC")
        {
            throw new ArgumentException("JWK must have kty=EC for Elliptic Curve keys");
        }

        if (!jwk.TryGetProperty("crv", out var crvElement) || crvElement.GetString() != "P-256")
        {
            throw new ArgumentException("Only P-256 curve is supported");
        }

        if (!jwk.TryGetProperty("x", out var xElement) || xElement.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException("JWK must contain 'x' coordinate");
        }

        if (!jwk.TryGetProperty("y", out var yElement) || yElement.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException("JWK must contain 'y' coordinate");
        }

        // Decode coordinates
        byte[] x, y;
        try
        {
            x = Base64UrlEncoder.DecodeBytes(xElement.GetString()!);
            y = Base64UrlEncoder.DecodeBytes(yElement.GetString()!);
        }
        catch (Exception ex) when (ex is FormatException or SdJwtException)
        {
            throw new ArgumentException("Invalid base64url encoding in JWK coordinates", ex);
        }

        // Validate coordinate sizes (P-256 uses 32-byte coordinates)
        if (x.Length != 32 || y.Length != 32)
        {
            throw new ArgumentException($"P-256 coordinates must be 32 bytes each. Got x={x.Length}, y={y.Length}");
        }

        // Create ECParameters and import to get SubjectPublicKeyInfo format
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = x,
                Y = y
            }
        };

        try
        {
            ecdsa.ImportParameters(parameters);
            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid EC public key parameters", ex);
        }
    }

    /// <summary>
    /// Converts a JWK from various formats (Dictionary or JsonElement) to ECDSA public key.
    /// Used when JWK is nested in cnf claim.
    /// </summary>
    /// <param name="jwkObject">The JWK as Dictionary or JsonElement.</param>
    /// <returns>The public key bytes in SubjectPublicKeyInfo format.</returns>
    public byte[] FromJwkObject(object jwkObject)
    {
        if (jwkObject is JsonElement jsonElement)
        {
            return FromJwk(jsonElement);
        }

        if (jwkObject is Dictionary<string, object> dict)
        {
            // Parse directly from dictionary for AOT compatibility
            return FromJwkDictionary(dict);
        }

        throw new ArgumentException("JWK must be a JsonElement or Dictionary<string, object>");
    }

    /// <summary>
    /// Converts a JWK dictionary to ECDSA public key (AOT-compatible, no JSON serialization).
    /// </summary>
    private byte[] FromJwkDictionary(Dictionary<string, object> dict)
    {
        // Validate required fields
        if (!dict.TryGetValue("kty", out var ktyObj) || ktyObj as string != "EC")
        {
            throw new ArgumentException("JWK must have kty=EC for Elliptic Curve keys");
        }

        if (!dict.TryGetValue("crv", out var crvObj) || crvObj as string != "P-256")
        {
            throw new ArgumentException("Only P-256 curve is supported");
        }

        if (!dict.TryGetValue("x", out var xObj) || xObj is not string xStr)
        {
            throw new ArgumentException("JWK must contain 'x' coordinate as a string");
        }

        if (!dict.TryGetValue("y", out var yObj) || yObj is not string yStr)
        {
            throw new ArgumentException("JWK must contain 'y' coordinate as a string");
        }

        // Decode coordinates
        byte[] x, y;
        try
        {
            x = Base64UrlEncoder.DecodeBytes(xStr);
            y = Base64UrlEncoder.DecodeBytes(yStr);
        }
        catch (Exception ex) when (ex is FormatException or SdJwtException)
        {
            throw new ArgumentException("Invalid base64url encoding in JWK coordinates", ex);
        }

        // Validate coordinate sizes (P-256 uses 32-byte coordinates)
        if (x.Length != 32 || y.Length != 32)
        {
            throw new ArgumentException($"P-256 coordinates must be 32 bytes each. Got x={x.Length}, y={y.Length}");
        }

        // Create ECParameters and import to get SubjectPublicKeyInfo format
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = x,
                Y = y
            }
        };

        try
        {
            ecdsa.ImportParameters(parameters);
            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid EC public key parameters", ex);
        }
    }
}
