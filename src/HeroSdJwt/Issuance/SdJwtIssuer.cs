using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Models;
using HeroSdJwt.Observability;
using HeroSdJwt.Presentation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Constants = HeroSdJwt.Primitives.Constants;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;
using SignatureAlgorithm = HeroSdJwt.Primitives.SignatureAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Creates SD-JWTs with selectively disclosable claims.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SdJwtIssuer"/> class with dependencies.
/// For simple usage: new SdJwtIssuer(new DisclosureGenerator(), new DigestCalculator(), new EcPublicKeyConverter(), new JwtSigner())
/// </remarks>
/// <param name="disclosureGenerator">The disclosure generator.</param>
/// <param name="digestCalculator">The digest calculator.</param>
/// <param name="ecPublicKeyConverter">The EC public key converter.</param>
/// <param name="jwtSigner">The JWT signer.</param>
/// <param name="logger">Optional logger for observability. If null, logging is disabled.</param>
public class SdJwtIssuer(
    IDisclosureGenerator disclosureGenerator,
    IDigestCalculator digestCalculator,
    IEcPublicKeyConverter ecPublicKeyConverter,
    IJwtSigner jwtSigner,
    ILogger<SdJwtIssuer>? logger = null) : ISdJwtIssuer
{
    private readonly IDisclosureGenerator disclosureGenerator = disclosureGenerator ?? throw new ArgumentNullException(nameof(disclosureGenerator));
    private readonly IDigestCalculator digestCalculator = digestCalculator ?? throw new ArgumentNullException(nameof(digestCalculator));
    private readonly IEcPublicKeyConverter ecPublicKeyConverter = ecPublicKeyConverter ?? throw new ArgumentNullException(nameof(ecPublicKeyConverter));
    private readonly IJwtSigner jwtSigner = jwtSigner ?? throw new ArgumentNullException(nameof(jwtSigner));
    private readonly ILogger<SdJwtIssuer> logger = logger ?? NullLogger<SdJwtIssuer>.Instance;

    /// <summary>
    /// Creates an SD-JWT with the specified claims and selective disclosure settings.
    /// </summary>
    /// <param name="claims">All claims to include in the JWT.</param>
    /// <param name="selectivelyDisclosableClaims">Claims that should be selectively disclosable.</param>
    /// <param name="signingKey">The signing key for JWT signature (format depends on algorithm).</param>
    /// <param name="hashAlgorithm">The hash algorithm for disclosure digests.</param>
    /// <param name="signatureAlgorithm">The signature algorithm for JWT signing (default: HS256).</param>
    /// <param name="holderPublicKey">Optional holder public key for key binding (cnf claim).</param>
    /// <param name="decoyDigestCount">Number of decoy digests to add for privacy protection (default: 0). Per SD-JWT spec section 4.2.5, decoy digests prevent claim enumeration.</param>
    /// <param name="keyId">Optional key identifier (kid) to include in JWT header for key rotation support (RFC 7515 Section 4.1.4).</param>
    /// <returns>The created SD-JWT.</returns>
    public SdJwt CreateSdJwt(
        Dictionary<string, object> claims,
        IEnumerable<string> selectivelyDisclosableClaims,
        byte[] signingKey,
        HashAlgorithm hashAlgorithm,
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256,
        byte[]? holderPublicKey = null,
        int decoyDigestCount = 0,
        string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(signingKey);

        var selectiveClaimsList = selectivelyDisclosableClaims?.ToList() ?? [];

        // Start distributed tracing activity
        using var activity = HeroSdJwtActivitySource.Instance.StartActivity("SdJwt.Issue");
        activity?.SetTag(HeroSdJwtActivitySource.Tags.Operation, "issue");
        activity?.SetTag(HeroSdJwtActivitySource.Tags.Algorithm, signatureAlgorithm.ToString());
        activity?.SetTag(HeroSdJwtActivitySource.Tags.HashAlgorithm, hashAlgorithm.ToString());
        activity?.SetTag(HeroSdJwtActivitySource.Tags.DecoyCount, decoyDigestCount);
        activity?.SetTag(HeroSdJwtActivitySource.Tags.HasKeyBinding, holderPublicKey != null);
        if (keyId != null)
        {
            activity?.SetTag(HeroSdJwtActivitySource.Tags.KeyId, keyId);
        }

        // Start performance measurement
        var stopwatch = Stopwatch.StartNew();

        try
        {
            // Log issuance start
            logger.LogIssuanceStarted(claims.Count, selectiveClaimsList.Count, decoyDigestCount);

            // Parse claim specifications to separate simple claims from array elements
            var parsedClaims = selectiveClaimsList.Select(ClaimPath.Parse).ToList();

            // Validate that security-critical claims are not selectively disclosable
            // Per SD-JWT spec section 5.3: "An Issuer MUST NOT allow any content to be
            // selectively disclosable that is critical for evaluating the SD-JWT's authenticity or validity"
            var reservedClaimsInList = parsedClaims
                .Where(p => !p.IsArrayElement && Constants.ReservedClaims.Contains(p.BaseName))
                .Select(p => p.BaseName)
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

            // Categorize claims by type
            var simpleTopLevelClaims = new List<ClaimPath>();
            var nestedClaims = new List<ClaimPath>();
            var arrayElementsToDisclose = new Dictionary<string, HashSet<int>>();

            foreach (var claimPath in parsedClaims)
            {
                if (claimPath.IsArrayElement)
                {
                    // Track array element for later processing
                    if (!arrayElementsToDisclose.ContainsKey(claimPath.BaseName))
                    {
                        arrayElementsToDisclose[claimPath.BaseName] = [];
                    }
                    arrayElementsToDisclose[claimPath.BaseName].Add(claimPath.ArrayIndex!.Value);
                }
                else if (claimPath.IsNested)
                {
                    // Nested property - process separately
                    nestedClaims.Add(claimPath);
                }
                else
                {
                    // Simple top-level claim
                    simpleTopLevelClaims.Add(claimPath);
                }
            }

            // Process simple top-level claims
            foreach (var claimPath in simpleTopLevelClaims)
            {
                if (claims.TryGetValue(claimPath.BaseName, out var claimValue))
                {
                    // Convert claim value to JsonElement
                    // Suppression: This is at the public API boundary where users provide arbitrary claim values.
                    // The library's internal processing is fully AOT-compatible (uses Utf8JsonWriter).
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement at API boundary
                    var jsonElement = JsonSerializer.SerializeToElement(claimValue);
#pragma warning restore IL2026, IL3050

                    // Generate disclosure
                    var disclosure = disclosureGenerator.GenerateDisclosure(claimPath.BaseName, jsonElement);
                    disclosures.Add(disclosure);

                    // Compute digest
                    var digest = digestCalculator.ComputeDigest(disclosure, hashAlgorithm);
                    digests.Add(digest);

                    // Log disclosure generation at debug level
                    logger.LogDisclosureGenerated(claimPath.BaseName);
                }
            }

            // Add decoy digests for privacy protection if requested
            // Per SD-JWT spec section 4.2.5: "The use of decoy digests is RECOMMENDED when the
            // number of claims (or the existence of particular claims) can be a side-channel
            // disclosing information about the End-User."
            if (decoyDigestCount > 0)
            {
                var decoyGenerator = new DecoyDigestGenerator(digestCalculator);
                var decoyDigests = decoyGenerator.GenerateDecoyDigests(decoyDigestCount, hashAlgorithm);
                digests = decoyGenerator.InterleaveDecoys(digests, decoyDigests);

                // Log decoy generation
                logger.LogDecoysGenerated(decoyDigestCount);
            }

            // Step 1.5: Process nested claims and build objects with _sd arrays
            var modifiedClaims = new Dictionary<string, object>(claims);

            if (nestedClaims.Count > 0)
            {
                var nestedProcessor = new NestedClaimProcessor(disclosureGenerator, digestCalculator);
                modifiedClaims = nestedProcessor.ProcessNestedClaims(
                    modifiedClaims,
                    nestedClaims,
                    hashAlgorithm,
                    disclosures);
            }

            // Step 2: Process array elements and generate their disclosures
            // This modifies the claims dictionary to replace selectively disclosable array elements with placeholders

            foreach (var (arrayClaimName, indicesToDisclose) in arrayElementsToDisclose)
            {
                if (!claims.TryGetValue(arrayClaimName, out var arrayValue))
                {
                    continue; // Array claim doesn't exist in claims
                }

                // Convert to JsonElement to work with array
                // Suppression: This is at the public API boundary where users provide arbitrary claim values.
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement at API boundary
                var arrayElement = JsonSerializer.SerializeToElement(arrayValue);
#pragma warning restore IL2026, IL3050

                if (arrayElement.ValueKind != JsonValueKind.Array)
                {
                    throw new ArgumentException(
                        $"Claim '{arrayClaimName}' is specified with array index syntax (e.g., '{arrayClaimName}[0]'), " +
                        "but the actual value is not an array.",
                        nameof(selectivelyDisclosableClaims));
                }

                var arrayLength = arrayElement.GetArrayLength();

                // Validate all indices are within bounds
                foreach (var index in indicesToDisclose)
                {
                    if (index >= arrayLength)
                    {
                        throw new ArgumentException(
                            $"Array index {index} is out of bounds for claim '{arrayClaimName}' which has {arrayLength} elements.",
                            nameof(selectivelyDisclosableClaims));
                    }
                }

                // Build new array with placeholders for selectively disclosable elements
                var newArray = new List<object>();

                for (int i = 0; i < arrayLength; i++)
                {
                    if (indicesToDisclose.Contains(i))
                    {
                        // This element should be selectively disclosable
                        var elementValue = arrayElement[i];

                        // Generate array element disclosure (2-element format)
                        var disclosure = disclosureGenerator.GenerateArrayElementDisclosure(elementValue);
                        disclosures.Add(disclosure);

                        // Compute digest
                        var digest = digestCalculator.ComputeDigest(disclosure, hashAlgorithm);
                        digests.Add(digest);

                        // Replace element with placeholder
                        newArray.Add(new Dictionary<string, string>
                    {
                        { "...", digest }
                    });
                    }
                    else
                    {
                        // Non-selectively-disclosable element - keep as-is
                        // Suppression: Converting JsonElement back to object for JWT payload construction.
#pragma warning disable IL2026, IL3050 // JsonSerializer.Deserialize at API boundary
                        newArray.Add(JsonSerializer.Deserialize<object>(arrayElement[i].GetRawText())!);
#pragma warning restore IL2026, IL3050
                    }
                }

                // Replace the original array with the modified one
                modifiedClaims[arrayClaimName] = newArray;
            }

            // Step 3: Build JWT payload
            var payload = new Dictionary<string, object>();

            // Get list of top-level claim names that are fully selectively disclosable
            // (not nested properties, which modify the base object instead)
            var fullySelectiveClaimNames = simpleTopLevelClaims
                .Select(p => p.BaseName)
                .ToHashSet();

            // Add non-selective claims, modified arrays, and objects with nested _sd
            foreach (var claim in modifiedClaims)
            {
                if (!fullySelectiveClaimNames.Contains(claim.Key))
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
                var jwk = ecPublicKeyConverter.ToJwk(holderPublicKey);
                payload["cnf"] = new Dictionary<string, object>
            {
                { "jwk", jwk }
            };
            }

            // Step 3: Create JWT using the specified signature algorithm
            var jwt = jwtSigner.CreateJwt(payload, signingKey, signatureAlgorithm, keyId);

            // Step 4: Compute claim path mapping for presentation performance optimization
            // This caches the mapping at issuance time to avoid recomputation on every presentation
            var claimPathMapper = new DisclosureClaimPathMapper(digestCalculator, new DisclosureParser());

            // Create temporary SdJwt to compute the mapping
            var tempSdJwt = new SdJwt(jwt, disclosures, hashAlgorithm);
            var claimPathMapping = claimPathMapper.BuildClaimPathMapping(tempSdJwt);

            // Step 5: Create final SdJwt object with cached mapping
            var sdJwt = new SdJwt(jwt, disclosures, hashAlgorithm, null, claimPathMapping);

            // Stop performance measurement
            stopwatch.Stop();

            // Log successful issuance
            logger.LogIssuanceCompleted(disclosures.Count, signatureAlgorithm.ToString());

            // Record metrics
            HeroSdJwtMetrics.IssuanceCount.Add(1,
                new KeyValuePair<string, object?>("algorithm", signatureAlgorithm.ToString()),
                new KeyValuePair<string, object?>("hash_algorithm", hashAlgorithm.ToString()));
            HeroSdJwtMetrics.IssuanceDuration.Record(stopwatch.Elapsed.TotalMilliseconds,
                new KeyValuePair<string, object?>("algorithm", signatureAlgorithm.ToString()));
            HeroSdJwtMetrics.UpdateLastDisclosureCount(disclosures.Count);

            // Set activity tags for successful completion
            activity?.SetTag(HeroSdJwtActivitySource.Tags.DisclosureCount, disclosures.Count);
            activity?.SetTag(HeroSdJwtActivitySource.Tags.ClaimCount, claims.Count);
            activity?.SetStatus(ActivityStatusCode.Ok);

            return sdJwt;
        }
        catch (Exception ex)
        {
            // Stop performance measurement
            stopwatch.Stop();

            // Log error
            logger.LogIssuanceFailed(ex, ex.Message);

            // Set activity error status
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.AddTag("error.type", ex.GetType().FullName);
            activity?.AddTag("error.message", ex.Message);

            // Re-throw the exception
            throw;
        }
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
}
