using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Interface for validating disclosure digests.
/// </summary>
public interface IDigestValidator
{
    /// <summary>
    /// Validates that a disclosure's computed digest matches the expected digest.
    /// </summary>
    /// <param name="disclosure">The base64url-encoded disclosure to validate.</param>
    /// <param name="expectedDigest">The expected digest from the JWT payload.</param>
    /// <param name="algorithm">The hash algorithm to use for digest computation.</param>
    /// <returns>True if the computed digest matches the expected digest; otherwise, false.</returns>
    bool ValidateDigest(string disclosure, Digest expectedDigest, HashAlgorithm algorithm);

    /// <summary>
    /// Validates all disclosures in a presentation against the digests in the JWT payload.
    /// </summary>
    /// <param name="disclosures">The list of base64url-encoded disclosures.</param>
    /// <param name="expectedDigests">The list of expected digests from the JWT payload.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>True if all disclosures have matching digests; otherwise, false.</returns>
    bool ValidateAllDigests(
        IReadOnlyList<string> disclosures,
        IReadOnlyList<Digest> expectedDigests,
        HashAlgorithm algorithm);
}
