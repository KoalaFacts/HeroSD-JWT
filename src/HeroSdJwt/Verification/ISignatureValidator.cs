using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Verification;

/// <summary>
/// Interface for validating JWT signatures.
/// </summary>
public interface ISignatureValidator
{
    /// <summary>
    /// Verifies the signature of a JWT.
    /// </summary>
    /// <param name="jwt">The JWT in format: header.payload.signature</param>
    /// <param name="publicKey">The public key or shared secret for verification.</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    bool VerifyJwtSignature(string jwt, byte[] publicKey);

    /// <summary>
    /// Verifies the signature of a JWT using key resolution.
    /// Extracts the 'kid' (key ID) from JWT header and uses the resolver to obtain the verification key.
    /// </summary>
    /// <param name="jwt">The JWT in format: header.payload.signature</param>
    /// <param name="keyResolver">Delegate to resolve key IDs to verification keys. Called only if JWT contains 'kid'.</param>
    /// <param name="fallbackKey">Optional fallback key to use when JWT has no 'kid' parameter (backward compatibility).</param>
    /// <returns>True if signature is valid; otherwise, false.</returns>
    /// <exception cref="SdJwtException">Thrown when JWT contains kid but resolver returns null (KeyIdNotFound), or when kid is present but no resolver/fallback provided (KeyResolverMissing), or when resolver throws an exception (KeyResolverFailed).</exception>
    bool VerifyJwtSignature(string jwt, KeyResolver? keyResolver, byte[]? fallbackKey = null);
}
