using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Verification;

/// <summary>
/// Validates disclosure digests using constant-time comparison to prevent timing attacks.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="DigestValidator"/> class with a digest calculator.
/// </remarks>
/// <param name="digestCalculator">The digest calculator to use.</param>
public class DigestValidator(IDigestCalculator digestCalculator) : IDigestValidator
{
    private readonly IDigestCalculator _digestCalculator = digestCalculator ?? throw new ArgumentNullException(nameof(digestCalculator));

    /// <summary>
    /// Initializes a new instance of the <see cref="DigestValidator"/> class.
    /// </summary>
    public DigestValidator()
        : this(new DigestCalculator())
    {
    }

    /// <summary>
    /// Validates that a disclosure's computed digest matches the expected digest.
    /// Uses constant-time comparison via CryptographicOperations.FixedTimeEquals to prevent timing attacks.
    /// </summary>
    /// <param name="disclosure">The base64url-encoded disclosure to validate.</param>
    /// <param name="expectedDigest">The expected digest from the JWT payload.</param>
    /// <param name="algorithm">The hash algorithm to use for digest computation.</param>
    /// <returns>True if the computed digest matches the expected digest; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when disclosure or expectedDigest is null.</exception>
    public bool ValidateDigest(string disclosure, Digest expectedDigest, HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        // Compute the digest for the given disclosure
        var computedDigestValue = _digestCalculator.ComputeDigest(disclosure, algorithm);
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
    public bool ValidateAllDigests(
        IReadOnlyList<string> disclosures,
        IReadOnlyList<Digest> expectedDigests,
        HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(expectedDigests);

        // RFC 9901 forbids repeating the same Disclosure. Enforce this also
        // for callers using the digest validator directly, rather than only
        // when the full presentation verifier is used.
        HashSet<string>? seenDisclosures = null;

        for (var i = 0; i < disclosures.Count; i++)
        {
            var disclosure = disclosures[i];
            if (i > 0)
            {
                // Avoid a set for the common zero/single-disclosure path.
                seenDisclosures ??= new HashSet<string>([disclosures[0]], StringComparer.Ordinal);
                if (!seenDisclosures.Add(disclosure))
                {
                    return false;
                }
            }

            // Validate each digest immediately. No need to retain a second
            // list of computed hashes for the duration of verification.
            var computedDigest = new Digest(
                _digestCalculator.ComputeDigest(disclosure, algorithm),
                algorithm);

            var found = false;
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
