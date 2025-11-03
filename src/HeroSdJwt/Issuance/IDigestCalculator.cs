using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Interface for calculating cryptographic digests of disclosure documents.
/// </summary>
public interface IDigestCalculator
{
    /// <summary>
    /// Computes the digest of a disclosure using the specified hash algorithm.
    /// </summary>
    /// <param name="disclosure">The base64url-encoded disclosure.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>The base64url-encoded digest.</returns>
    string ComputeDigest(string disclosure, HashAlgorithm algorithm);
}
