using HeroSdJwt.Primitives;
using System.Buffers.Text;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Generates decoy digests for privacy protection in SD-JWT.
/// Per SD-JWT spec section 4.2.5, decoy digests prevent enumeration of the number
/// of selectively disclosable claims by adding fake digests that look real.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="DecoyDigestGenerator"/> class with dependencies.
/// For simple usage: new DecoyDigestGenerator(new DigestCalculator())
/// </remarks>
/// <param name="digestCalculator">The digest calculator to use.</param>
public class DecoyDigestGenerator(IDigestCalculator digestCalculator) : IDecoyDigestGenerator
{
    // SHA-256 produces at least 43 base64url characters per digest. More
    // than this many decoys cannot fit in even an otherwise empty 64-KiB JWT.
    // Leave tighter serialized-size admission to the existing JWT signer.
    internal const int MAXIMUM_DECOY_DIGESTS = Constants.MAX_JWT_SIZE_BYTES / 43;

    private readonly IDigestCalculator _digestCalculator = digestCalculator ?? throw new ArgumentNullException(nameof(digestCalculator));

    /// <summary>
    /// Generates the specified number of decoy digests using cryptographically secure random data.
    /// Per spec recommendation: "create the decoy digests by hashing over a cryptographically secure random number"
    /// </summary>
    /// <param name="count">Number of decoy digests to generate.</param>
    /// <param name="hashAlgorithm">Hash algorithm to use (must match real disclosures).</param>
    /// <returns>List of decoy digest strings.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The requested count cannot fit within the JWT size limit.</exception>
    public List<string> GenerateDecoyDigests(int count, HashAlgorithm hashAlgorithm)
    {
        if (count < 0)
        {
            throw new ArgumentException("Count cannot be negative", nameof(count));
        }

        // Reject impossible counts before the capacity allocation and hash loop.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, MAXIMUM_DECOY_DIGESTS, nameof(count));

        if (count == 0)
        {
            return [];
        }

        var decoys = new List<string>(count);
        // Reuse fixed stack storage: a fresh 256-bit cryptographic value is
        // generated for each decoy without allocating a temporary byte[].
        Span<byte> randomBytes = stackalloc byte[32];

        for (int i = 0; i < count; i++)
        {
            RandomNumberGenerator.Fill(randomBytes);

            // Encode a fresh random disclosure without allocating a byte[].
            var randomDisclosure = Base64Url.EncodeToString(randomBytes);

            // Compute digest of the random data
            var decoyDigest = _digestCalculator.ComputeDigest(randomDisclosure, hashAlgorithm);
            decoys.Add(decoyDigest);
        }

        return decoys;
    }

    /// <summary>
    /// Randomly interleaves decoy digests with real digests.
    /// This prevents pattern-based detection of which digests are real vs. decoys.
    /// </summary>
    /// <param name="realDigests">The real disclosure digests.</param>
    /// <param name="decoyDigests">The decoy digests.</param>
    /// <returns>Combined list with decoys randomly distributed.</returns>
    public List<string> InterleaveDecoys(List<string> realDigests, List<string> decoyDigests)
    {
        ArgumentNullException.ThrowIfNull(realDigests);
        ArgumentNullException.ThrowIfNull(decoyDigests);

        if (decoyDigests.Count == 0)
        {
            return [.. realDigests];
        }

        // Combine all digests
        var allDigests = new List<string>(realDigests.Count + decoyDigests.Count);
        allDigests.AddRange(realDigests);
        allDigests.AddRange(decoyDigests);

        // Shuffle using Fisher-Yates algorithm with cryptographically secure random
        for (int i = allDigests.Count - 1; i > 0; i--)
        {
            // Get cryptographically secure random index
            var j = RandomNumberGenerator.GetInt32(i + 1);

            // Swap
            (allDigests[i], allDigests[j]) = (allDigests[j], allDigests[i]);
        }

        return allDigests;
    }
}
