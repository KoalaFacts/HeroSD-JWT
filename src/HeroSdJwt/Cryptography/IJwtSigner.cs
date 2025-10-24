using HeroSdJwt.Primitives;

namespace HeroSdJwt.Cryptography;

/// <summary>
/// Interface for creating and signing JWTs.
/// </summary>
public interface IJwtSigner
{
    /// <summary>
    /// Creates a signed JWT with the specified payload and algorithm.
    /// </summary>
    /// <param name="payload">JWT payload claims.</param>
    /// <param name="signingKey">Signing key (format depends on algorithm).</param>
    /// <param name="algorithm">Signature algorithm to use.</param>
    /// <returns>Signed JWT in format: header.payload.signature</returns>
    string CreateJwt(
        Dictionary<string, object> payload,
        byte[] signingKey,
        SignatureAlgorithm algorithm);
}
