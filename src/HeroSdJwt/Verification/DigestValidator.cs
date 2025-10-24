using System.Security.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Validates disclosure digests using constant-time comparison to prevent timing attacks.
/// </summary>
internal static class DigestValidator
{
    /// <summary>
    /// Validates that a disclosure's computed digest matches the expected digest.
    /// Uses constant-time comparison via CryptographicOperations.FixedTimeEquals to prevent timing attacks.
    /// </summary>
    /// <param name="disclosure">The base64url-encoded disclosure to validate.</param>
    /// <param name="expectedDigest">The expected digest from the JWT payload.</param>
    /// <param name="algorithm">The hash algorithm to use for digest computation.</param>
    /// <returns>True if the computed digest matches the expected digest; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when disclosure or expectedDigest is null.</exception>
    public static bool ValidateDigest(string disclosure, Digest expectedDigest, HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        // Compute the digest for the given disclosure
        var calculator = new DigestCalculator();
        var computedDigestValue = calculator.ComputeDigest(disclosure, algorithm);
        var computedDigest = new Digest(computedDigestValue, algorithm);

        // Use constant-time comparison from Digest.Equals (which uses CryptographicOperations.FixedTimeEquals)
        return computedDigest.Equals(expectedDigest);
    }

    /// <summary>
    /// Validates all disclosures in a presentation against the digests in the JWT payload.
    /// </summary>
    /// <param name="disclosures">The list of base64url-encoded disclosures.</param>
    /// <param name="expectedDigests">The list of expected digests from the JWT payload.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>True if all disclosures have matching digests; otherwise, false.</returns>
    public static bool ValidateAllDigests(
        IReadOnlyList<string> disclosures,
        IReadOnlyList<Digest> expectedDigests,
        HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(expectedDigests);

        // Compute digests for all disclosures
        var calculator = new DigestCalculator();
        var computedDigests = new List<Digest>();

        foreach (var disclosure in disclosures)
        {
            var digestValue = calculator.ComputeDigest(disclosure, algorithm);
            computedDigests.Add(new Digest(digestValue, algorithm));
        }

        // Check that every computed digest exists in the expected digests
        // This ensures all disclosures are valid without revealing which specific disclosure failed
        foreach (var computedDigest in computedDigests)
        {
            bool found = false;
            foreach (var expectedDigest in expectedDigests)
            {
                if (computedDigest.Equals(expectedDigest))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                return false;
            }
        }

        return true;
    }
}
