using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;
using SignatureAlgorithm = HeroSdJwt.Primitives.SignatureAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Interface for SD-JWT issuance with selective disclosure.
/// Allows for dependency injection and testing with mock implementations.
/// </summary>
public interface ISdJwtIssuer
{
    /// <summary>
    /// Creates an SD-JWT with the specified claims and selective disclosure settings.
    /// </summary>
    /// <param name="claims">All claims to include in the JWT.</param>
    /// <param name="selectivelyDisclosableClaims">Claims that should be selectively disclosable.</param>
    /// <param name="signingKey">The signing key for JWT signature (format depends on algorithm).</param>
    /// <param name="hashAlgorithm">The hash algorithm for disclosure digests.</param>
    /// <param name="signatureAlgorithm">The signature algorithm for JWT signing (default: HS256).</param>
    /// <param name="holderPublicKey">Optional holder public key for key binding (cnf claim).</param>
    /// <param name="decoyDigestCount">Number of decoy digests to add for privacy protection (default: 0).</param>
    /// <param name="keyId">Optional key identifier (kid) to include in JWT header for key rotation support.</param>
    /// <returns>The created SD-JWT.</returns>
    SdJwt CreateSdJwt(
        Dictionary<string, object> claims,
        IEnumerable<string> selectivelyDisclosableClaims,
        byte[] signingKey,
        HashAlgorithm hashAlgorithm,
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256,
        byte[]? holderPublicKey = null,
        int decoyDigestCount = 0,
        string? keyId = null);
}
