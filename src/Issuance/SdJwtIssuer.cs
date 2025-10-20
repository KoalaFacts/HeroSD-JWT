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
    /// <param name="holderPublicKey">Optional holder public key for key binding (cnf claim).</param>
    /// <param name="decoyDigestCount">Number of decoy digests to add for privacy protection (default: 0). Per SD-JWT spec section 4.2.5, decoy digests prevent claim enumeration.</param>
    /// <returns>The created SD-JWT.</returns>
    public SdJwt CreateSdJwt(
        Dictionary<string, object> claims,
        IEnumerable<string> selectivelyDisclosableClaims,
        byte[] signingKey,
        HashAlgorithm hashAlgorithm,
        byte[]? holderPublicKey = null,
        int decoyDigestCount = 0)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(signingKey);

        var selectiveClaimsList = selectivelyDisclosableClaims?.ToList() ?? new List<string>();

        // Validate that security-critical claims are not selectively disclosable
        // Per SD-JWT spec section 5.3: "An Issuer MUST NOT allow any content to be
        // selectively disclosable that is critical for evaluating the SD-JWT's authenticity or validity"
        var reservedClaimsInList = selectiveClaimsList
            .Where(c => Core.Constants.ReservedClaims.Contains(c))
            .ToList();

        if (reservedClaimsInList.Any())
        {
            throw new ArgumentException(
                $"The following security-critical claims cannot be selectively disclosable: {string.Join(", ", reservedClaimsInList)}. " +
                "Per SD-JWT specification section 5.3, claims like iss, aud, exp, nbf, cnf, iat, sub, jti, _sd, and _sd_alg " +
                "are critical for evaluating authenticity and validity and must remain visible in the JWT payload.",
                nameof(selectivelyDisclosableClaims));
        }

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

        // Add decoy digests for privacy protection if requested
        // Per SD-JWT spec section 4.2.5: "The use of decoy digests is RECOMMENDED when the
        // number of claims (or the existence of particular claims) can be a side-channel
        // disclosing information about the End-User."
        if (decoyDigestCount > 0)
        {
            var decoyGenerator = new DecoyDigestGenerator();
            var decoyDigests = decoyGenerator.GenerateDecoyDigests(decoyDigestCount, hashAlgorithm);
            digests = decoyGenerator.InterleaveDecoys(digests, decoyDigests);
        }

        // Step 2: Build JWT payload
        var payload = new Dictionary<string, object>();

        // Add non-selective claims
        foreach (var claim in claims)
        {
            if (!selectiveClaimsList.Contains(claim.Key))
            {
                // Validate _sd_alg placement - MUST only appear at top level
                // Per SD-JWT spec section 4.2.3: "_sd_alg MUST appear at the top level
                // of the SD-JWT payload and MUST NOT be used in any object nested within the payload"
                if (claim.Key == Constants.SdAlgClaimName)
                {
                    throw new ArgumentException(
                        $"The claim '{Constants.SdAlgClaimName}' is reserved for internal use and cannot be explicitly set. " +
                        "The hash algorithm is specified via the hashAlgorithm parameter.",
                        nameof(claims));
                }

                // Check for nested _sd_alg in object values
                ValidateNoNestedSdAlg(claim.Value, claim.Key);

                payload[claim.Key] = claim.Value;
            }
        }

        // Add SD-JWT specific claims
        if (digests.Count > 0)
        {
            payload[Constants.SdClaimName] = digests;
        }

        payload[Constants.SdAlgClaimName] = Constants.HashAlgorithmNames[hashAlgorithm];

        // Add cnf claim if holder public key is provided (for key binding)
        // Per RFC 7800 and SD-JWT spec section 4.3, use proper JWK format
        if (holderPublicKey != null)
        {
            var jwk = Common.JwkHelper.CreateEcPublicKeyJwk(holderPublicKey);
            payload["cnf"] = new Dictionary<string, object>
            {
                { "jwk", jwk }
            };
        }

        // Step 3: Create JWT
        var jwt = CreateJwt(payload, signingKey);

        // Step 4: Create SdJwt object
        return new SdJwt(jwt, disclosures, hashAlgorithm);
    }

    /// <summary>
    /// Recursively validates that _sd_alg does not appear in nested objects.
    /// Per SD-JWT spec section 4.2.3, _sd_alg MUST only appear at top level.
    /// </summary>
    private static void ValidateNoNestedSdAlg(object value, string claimPath)
    {
        if (value is Dictionary<string, object> dict)
        {
            foreach (var kvp in dict)
            {
                if (kvp.Key == Constants.SdAlgClaimName)
                {
                    throw new ArgumentException(
                        $"The claim '{Constants.SdAlgClaimName}' was found in nested object at path '{claimPath}.{kvp.Key}'. " +
                        "Per SD-JWT specification section 4.2.3, _sd_alg MUST appear at the top level of the SD-JWT payload " +
                        "and MUST NOT be used in any object nested within the payload.",
                        nameof(value));
                }

                ValidateNoNestedSdAlg(kvp.Value, $"{claimPath}.{kvp.Key}");
            }
        }
        else if (value is System.Collections.IEnumerable enumerable and not string)
        {
            var index = 0;
            foreach (var item in enumerable)
            {
                ValidateNoNestedSdAlg(item, $"{claimPath}[{index}]");
                index++;
            }
        }
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
