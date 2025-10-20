using HeroSdJwt.Common;
using HeroSdJwt.Core;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Creates SD-JWTs with selectively disclosable claims.
/// </summary>
public class SdJwtIssuer
{
    private readonly DisclosureGenerator disclosureGenerator;
    private readonly DigestCalculator digestCalculator;

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtIssuer"/> class.
    /// </summary>
    public SdJwtIssuer()
    {
        disclosureGenerator = new DisclosureGenerator();
        digestCalculator = new DigestCalculator();
    }

    /// <summary>
    /// Creates an SD-JWT with the specified claims and selective disclosure settings.
    /// </summary>
    /// <param name="claims">All claims to include in the JWT.</param>
    /// <param name="selectivelyDisclosableClaims">Claims that should be selectively disclosable.</param>
    /// <param name="signingKey">The signing key for JWT signature.</param>
    /// <param name="hashAlgorithm">The hash algorithm for disclosure digests.</param>
    /// <returns>The created SD-JWT.</returns>
    public SdJwt CreateSdJwt(
        Dictionary<string, object> claims,
        IEnumerable<string> selectivelyDisclosableClaims,
        byte[] signingKey,
        HashAlgorithm hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(signingKey);

        var selectiveClaimsList = selectivelyDisclosableClaims?.ToList() ?? new List<string>();

        // Step 1: Generate disclosures for selectively disclosable claims
        var disclosures = new List<string>();
        var digests = new List<string>();

        foreach (var claimName in selectiveClaimsList)
        {
            if (claims.TryGetValue(claimName, out var claimValue))
            {
                // Convert claim value to JsonElement
                var jsonElement = JsonSerializer.SerializeToElement(claimValue);

                // Generate disclosure
                var disclosure = disclosureGenerator.GenerateDisclosure(claimName, jsonElement);
                disclosures.Add(disclosure);

                // Compute digest
                var digest = digestCalculator.ComputeDigest(disclosure, hashAlgorithm);
                digests.Add(digest);
            }
        }

        // Step 2: Build JWT payload
        var payload = new Dictionary<string, object>();

        // Add non-selective claims
        foreach (var claim in claims)
        {
            if (!selectiveClaimsList.Contains(claim.Key))
            {
                payload[claim.Key] = claim.Value;
            }
        }

        // Add SD-JWT specific claims
        if (digests.Count > 0)
        {
            payload[Constants.SdClaimName] = digests;
        }

        payload[Constants.SdAlgClaimName] = Constants.HashAlgorithmNames[hashAlgorithm];

        // Step 3: Create JWT
        var jwt = CreateJwt(payload, signingKey);

        // Step 4: Create SdJwt object
        return new SdJwt(jwt, disclosures, hashAlgorithm);
    }

    /// <summary>
    /// Creates a simple JWT with HMAC-SHA256 signature.
    /// This is a minimal implementation for testing purposes.
    /// Production code should use a proper JWT library.
    /// </summary>
    private static string CreateJwt(Dictionary<string, object> payload, byte[] signingKey)
    {
        // Create header
        var header = new Dictionary<string, object>
        {
            { "alg", "HS256" },
            { "typ", "JWT" }
        };

        var headerJson = JsonSerializer.Serialize(header);
        var headerBase64 = Base64UrlEncoder.Encode(headerJson);

        var payloadJson = JsonSerializer.Serialize(payload);
        var payloadBase64 = Base64UrlEncoder.Encode(payloadJson);

        // Create signature
        var message = $"{headerBase64}.{payloadBase64}";
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var signatureBytes = HMACSHA256.HashData(signingKey, messageBytes);
        var signatureBase64 = Base64UrlEncoder.Encode(signatureBytes);

        return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
    }
}
