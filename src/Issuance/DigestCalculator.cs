using HeroSdJwt.Common;
using System.Security.Cryptography;
using System.Text;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Calculates cryptographic digests of disclosure documents.
/// Digest = Base64url(Hash(disclosure))
/// </summary>
public class DigestCalculator
{
    /// <summary>
    /// Computes the digest of a disclosure using the specified hash algorithm.
    /// </summary>
    /// <param name="disclosure">The base64url-encoded disclosure.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>The base64url-encoded digest.</returns>
    public string ComputeDigest(string disclosure, HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        if (string.IsNullOrWhiteSpace(disclosure))
        {
            throw new ArgumentException("Disclosure cannot be empty or whitespace.", nameof(disclosure));
        }

        // Convert disclosure to bytes (it's already UTF-8 string)
        var disclosureBytes = Encoding.UTF8.GetBytes(disclosure);

        // Compute hash based on algorithm
        byte[] hashBytes = algorithm switch
        {
            HashAlgorithm.Sha256 => SHA256.HashData(disclosureBytes),
            HashAlgorithm.Sha384 => SHA384.HashData(disclosureBytes),
            HashAlgorithm.Sha512 => SHA512.HashData(disclosureBytes),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithm}", nameof(algorithm))
        };

        // Convert hash to base64url
        return Base64UrlEncoder.Encode(hashBytes);
    }
}
