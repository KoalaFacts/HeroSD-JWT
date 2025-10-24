using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Interface for generating decoy digests for privacy protection in SD-JWT.
/// Per SD-JWT spec section 4.2.5, decoy digests prevent enumeration of the number
/// of selectively disclosable claims by adding fake digests that look real.
/// </summary>
public interface IDecoyDigestGenerator
{
    /// <summary>
    /// Generates the specified number of decoy digests using cryptographically secure random data.
    /// Per spec recommendation: "create the decoy digests by hashing over a cryptographically secure random number"
    /// </summary>
    /// <param name="count">Number of decoy digests to generate.</param>
    /// <param name="hashAlgorithm">Hash algorithm to use (must match real disclosures).</param>
    /// <returns>List of decoy digest strings.</returns>
    List<string> GenerateDecoyDigests(int count, HashAlgorithm hashAlgorithm);

    /// <summary>
    /// Randomly interleaves decoy digests with real digests.
    /// This prevents pattern-based detection of which digests are real vs. decoys.
    /// </summary>
    /// <param name="realDigests">The real disclosure digests.</param>
    /// <param name="decoyDigests">The decoy digests.</param>
    /// <returns>Combined list with decoys randomly distributed.</returns>
    List<string> InterleaveDecoys(List<string> realDigests, List<string> decoyDigests);
}
