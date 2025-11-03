using System.Text.Json;

namespace HeroSdJwt.Cryptography;

/// <summary>
/// Converts between ECDSA public keys and JSON Web Key (JWK) format per RFC 7517.
/// Handles P-256 elliptic curve keys for SD-JWT key binding.
/// </summary>
public interface IEcPublicKeyConverter
{
    /// <summary>
    /// Converts an ECDSA public key to JWK (JSON Web Key) format.
    /// </summary>
    /// <param name="publicKeyBytes">The public key in SubjectPublicKeyInfo format.</param>
    /// <returns>A dictionary representing the JWK with kty, crv, x, y parameters.</returns>
    /// <exception cref="ArgumentException">If the key is invalid or not P-256.</exception>
    Dictionary<string, object> ToJwk(byte[] publicKeyBytes);

    /// <summary>
    /// Converts a JWK (JSON Web Key) to ECDSA public key format.
    /// </summary>
    /// <param name="jwk">The JWK as a JsonElement.</param>
    /// <returns>The public key bytes in SubjectPublicKeyInfo format.</returns>
    /// <exception cref="ArgumentException">If the JWK is invalid or not P-256.</exception>
    byte[] FromJwk(JsonElement jwk);

    /// <summary>
    /// Converts a JWK from various formats (Dictionary or JsonElement) to ECDSA public key.
    /// Used when JWK is nested in cnf claim.
    /// </summary>
    /// <param name="jwkObject">The JWK as Dictionary or JsonElement.</param>
    /// <returns>The public key bytes in SubjectPublicKeyInfo format.</returns>
    byte[] FromJwkObject(object jwkObject);
}
