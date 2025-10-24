using System.Security.Cryptography;
using HeroSdJwt.Encoding;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Generates decoy digests for privacy protection in SD-JWT.
/// Per SD-JWT spec section 4.2.5, decoy digests prevent enumeration of the number
/// of selectively disclosable claims by adding fake digests that look real.
/// </summary>
internal class DecoyDigestGenerator
{
    private readonly IDigestCalculator digestCalculator;

    /// <summary>
    /// Initializes a new instance of the <see cref="DecoyDigestGenerator"/> class.
    /// </summary>
    public DecoyDigestGenerator()
        : this(new DigestCalculator())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DecoyDigestGenerator"/> class with dependencies.
    /// </summary>
    /// <param name="digestCalculator">The digest calculator to use.</param>
    internal DecoyDigestGenerator(DigestCalculator digestCalculator)
    {
        this.digestCalculator = digestCalculator ?? throw new ArgumentNullException(nameof(digestCalculator));
    }

    /// <summary>
    /// Generates the specified number of decoy digests using cryptographically secure random data.
    /// Per spec recommendation: "create the decoy digests by hashing over a cryptographically secure random number"
    /// </summary>
    /// <param name="count">Number of decoy digests to generate.</param>
    /// <param name="hashAlgorithm">Hash algorithm to use (must match real disclosures).</param>
    /// <returns>List of decoy digest strings.</returns>
    public List<string> GenerateDecoyDigests(int count, HashAlgorithm hashAlgorithm)
    {
        if (count < 0)
        {
            throw new ArgumentException("Count cannot be negative", nameof(count));
        }

        if (count == 0)
        {
            return new List<string>();
        }

        var decoys = new List<string>(count);

        for (int i = 0; i < count; i++)
        {
            // Generate cryptographically secure random bytes
            // Use 32 bytes (256 bits) for good entropy
            var randomBytes = new byte[32];
            RandomNumberGenerator.Fill(randomBytes);

            // Convert to base64url (simulating a disclosure format)
            var randomDisclosure = Base64UrlEncoder.Encode(randomBytes);

            // Compute digest of the random data
            var decoyDigest = digestCalculator.ComputeDigest(randomDisclosure, hashAlgorithm);
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
            return new List<string>(realDigests);
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
