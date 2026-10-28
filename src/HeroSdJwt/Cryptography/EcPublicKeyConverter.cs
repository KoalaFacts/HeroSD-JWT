using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Cryptography;

/// <summary>
/// Converts between ECDSA public keys and JSON Web Key (JWK) format per RFC 7517.
/// Handles P-256 elliptic curve keys for SD-JWT key binding.
/// </summary>
public class EcPublicKeyConverter : IEcPublicKeyConverter
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
        int bytesRead;
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out bytesRead);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid ECDSA public key format", nameof(publicKeyBytes), ex);
        }
        catch (PlatformNotSupportedException ex)
        {
            // Unsupported curves must not bypass the ES256 key policy.
            throw new ArgumentException("Unsupported ECDSA public key curve", nameof(publicKeyBytes), ex);
        }

        // ImportSubjectPublicKeyInfo reads only the first ASN.1 value. Do not
        // silently normalize a key blob carrying additional, untrusted data.
        if (bytesRead != publicKeyBytes.Length)
        {
            throw new ArgumentException("ECDSA public key must contain exactly one SPKI value without trailing bytes", nameof(publicKeyBytes));
        }

        // Only P-256 is supported for ES256
        if (!EcCurveGuard.IsP256(ecdsa))
        {
            throw new ArgumentException(
                $"Only P-256 (256-bit) elliptic curve is supported. Provided key is {ecdsa.KeySize}-bit; ES256 requires the named NIST P-256 curve.",
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
        // JSON member lookup is last-wins. Reject repeated names (including
        // escaped aliases) instead of converting an ambiguous holder key.
        if (JsonObjectMemberGuard.HasInvalidOrDuplicateNames(jwk))
        {
            throw new ArgumentException("JWK must be an object with unique, valid member names", nameof(jwk));
        }

        // RFC 7800's asymmetric holder confirmation uses the public JWK.
        // Never accept embedded EC private key material in the JWT's cnf.
        if (jwk.TryGetProperty("d", out _))
        {
            throw new ArgumentException("Holder confirmation JWK must not contain private key material", nameof(jwk));
        }

        // Holder confirmation uses a public ES256 verification key. Do not
        // accept hidden symmetric material or JWK metadata authorizing a
        // different algorithm or operation.
        ValidatePublicVerificationMetadata(jwk);

        // Validate required fields
        if (!jwk.TryGetProperty("kty", out var ktyElement) || ktyElement.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException("JWK must have kty=EC for Elliptic Curve keys");
        }

        if (ktyElement.GetString() != "EC")
        {
            throw new ArgumentException("JWK must have kty=EC for Elliptic Curve keys");
        }

        if (!jwk.TryGetProperty("crv", out var crvElement) || crvElement.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException("Only P-256 curve is supported");
        }

        if (crvElement.GetString() != "P-256")
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
        // Apply the same public-only rule to dictionary-based JWK inputs.
        if (dict.ContainsKey("d"))
        {
            throw new ArgumentException("Holder confirmation JWK must not contain private key material", nameof(dict));
        }

        ValidatePublicVerificationMetadata(dict);

        // Validate required fields
        if (!dict.TryGetValue("kty", out var ktyObj))
        {
            throw new ArgumentException("JWK must have kty=EC for Elliptic Curve keys");
        }

        if (GetJwkString(ktyObj) != "EC")
        {
            throw new ArgumentException("JWK must have kty=EC for Elliptic Curve keys");
        }

        if (!dict.TryGetValue("crv", out var crvObj))
        {
            throw new ArgumentException("Only P-256 curve is supported");
        }

        if (GetJwkString(crvObj) != "P-256")
        {
            throw new ArgumentException("Only P-256 curve is supported");
        }

        if (!dict.TryGetValue("x", out var xObj) || GetJwkString(xObj) is not string xStr)
        {
            throw new ArgumentException("JWK must contain 'x' coordinate as a string");
        }

        if (!dict.TryGetValue("y", out var yObj) || GetJwkString(yObj) is not string yStr)
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

    private static void ValidatePublicVerificationMetadata(JsonElement jwk)
    {
        if (jwk.TryGetProperty("k", out _))
        {
            throw new ArgumentException("An EC public JWK must not contain symmetric key material", nameof(jwk));
        }

        if (jwk.TryGetProperty("use", out var use) &&
            (use.ValueKind != JsonValueKind.String || use.GetString() != "sig"))
        {
            throw new ArgumentException("Holder JWK use must be sig when present", nameof(jwk));
        }

        if (jwk.TryGetProperty("alg", out var alg) &&
            (alg.ValueKind != JsonValueKind.String || alg.GetString() != "ES256"))
        {
            throw new ArgumentException("Holder JWK alg must be ES256 when present", nameof(jwk));
        }

        if (jwk.TryGetProperty("key_ops", out var operations) &&
            !HasOnlyVerifyOperation(operations))
        {
            throw new ArgumentException("Holder public JWK key_ops must contain only verify", nameof(jwk));
        }
    }

    private static void ValidatePublicVerificationMetadata(Dictionary<string, object> jwk)
    {
        if (jwk.ContainsKey("k"))
        {
            throw new ArgumentException("An EC public JWK must not contain symmetric key material", nameof(jwk));
        }

        if (jwk.TryGetValue("use", out var use) && GetJwkString(use) != "sig")
        {
            throw new ArgumentException("Holder JWK use must be sig when present", nameof(jwk));
        }

        if (jwk.TryGetValue("alg", out var alg) && GetJwkString(alg) != "ES256")
        {
            throw new ArgumentException("Holder JWK alg must be ES256 when present", nameof(jwk));
        }

        if (jwk.TryGetValue("key_ops", out var operations) &&
            !HasOnlyVerifyOperation(operations))
        {
            throw new ArgumentException("Holder public JWK key_ops must contain only verify", nameof(jwk));
        }
    }

    // System.Text.Json's Dictionary<string, object> deserializer retains scalar
    // values as JsonElement. Honor the same string-only JWK policy for either
    // representation without enabling arbitrary ToString() coercions.
    private static string? GetJwkString(object? value) => value switch
    {
        string text => text,
        JsonElement { ValueKind: JsonValueKind.String } element => element.GetString(),
        _ => null
    };

    private static bool HasOnlyVerifyOperation(JsonElement operations) =>
        operations.ValueKind == JsonValueKind.Array &&
        operations.GetArrayLength() == 1 &&
        operations[0].ValueKind == JsonValueKind.String &&
        operations[0].GetString() == "verify";

    private static bool HasOnlyVerifyOperation(object? operations)
    {
        if (operations is JsonElement json)
        {
            return HasOnlyVerifyOperation(json);
        }

        if (operations is not System.Collections.IEnumerable enumerable)
        {
            return false;
        }

        var found = false;
        foreach (var item in enumerable)
        {
            if (found ||
                (item is not "verify" &&
                 (item is not JsonElement element ||
                  element.ValueKind != JsonValueKind.String ||
                  element.GetString() != "verify")))
            {
                return false;
            }

            found = true;
        }

        return found;
    }
}
