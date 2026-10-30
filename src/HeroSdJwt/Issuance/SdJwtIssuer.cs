using HeroSdJwt.Cryptography;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Verification;
using System.Text.Json;
using Constants = HeroSdJwt.Primitives.Constants;
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
/// <param name="_disclosureGenerator">The disclosure generator.</param>
/// <param name="_digestCalculator">The digest calculator.</param>
/// <param name="ecPublicKeyConverter">The EC public key converter.</param>
/// <param name="_jwtSigner">The JWT signer.</param>
public class SdJwtIssuer(
    IDisclosureGenerator _disclosureGenerator,
    IDigestCalculator _digestCalculator,
    IEcPublicKeyConverter ecPublicKeyConverter,
    IJwtSigner _jwtSigner) : ISdJwtIssuer
{
    private readonly IDisclosureGenerator _disclosureGenerator = _disclosureGenerator ?? throw new ArgumentNullException(nameof(_disclosureGenerator));
    private readonly IDigestCalculator _digestCalculator = _digestCalculator ?? throw new ArgumentNullException(nameof(_digestCalculator));
    private readonly IEcPublicKeyConverter _ecPublicKeyConverter = ecPublicKeyConverter ?? throw new ArgumentNullException(nameof(ecPublicKeyConverter));
    private readonly IJwtSigner _jwtSigner = _jwtSigner ?? throw new ArgumentNullException(nameof(_jwtSigner));

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

        // SD-JWT spec requires an expiration claim. Generate the default without
        // modifying the caller's dictionary, even when later validation fails.
        var hasExplicitExpiration = claims.TryGetValue("exp", out var expClaim);
        if (!hasExplicitExpiration)
        {
            expClaim = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        }

        try
        {
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement at API boundary
            var expElement = JsonSerializer.SerializeToElement(expClaim);
#pragma warning restore IL2026, IL3050
            if (!NumericDateParser.TryParseUnixTicks(expElement, out _))
            {
                throw new ArgumentException(
                    "The 'exp' claim must be a representable numeric Unix timestamp (seconds since epoch).",
                    nameof(claims));
            }
        }
        catch (JsonException ex)
        {
            throw new ArgumentException(
                "The 'exp' claim must be a numeric Unix timestamp (seconds since epoch).",
                nameof(claims),
                ex);
        }

        var selectiveClaimsList = selectivelyDisclosableClaims?.ToList() ?? [];

        // Repeating the same selective path must not create multiple salted
        // Disclosures: that would make claim-path mapping ambiguous at issuance.
        // Keep the first occurrence and preserve ordinal (case-sensitive) paths.
        if (selectiveClaimsList.Count > 1)
        {
            var seenPaths = new HashSet<string>(StringComparer.Ordinal);
            selectiveClaimsList.RemoveAll(path => !seenPaths.Add(path));
        }

        try
        {
            // Parse claim specifications to separate simple claims from array elements
            // RFC 7519 allows URI-valued claim names. Treat URI-shaped
            // selectors as literal top-level members, not nested paths;
            // ordinary dot and array selectors keep their existing meaning.
            var parsedClaims = selectiveClaimsList.Select(path =>
            {
                ArgumentNullException.ThrowIfNull(path);
                return path.Contains('/') && Uri.TryCreate(path, UriKind.Absolute, out _)
                    ? ClaimPath.ForLiteralTopLevelName(path)
                    : ClaimPath.Parse(path);
            }).ToList();

            // Validate that security-critical claims are not selectively disclosable
            // Per SD-JWT spec section 5.3: "An Issuer MUST NOT allow any content to be
            // selectively disclosable that is critical for evaluating the SD-JWT's authenticity or validity"
            // Even one disclosed array element would conceal part of a
            // security-critical claim such as an RFC 7519 audience array.
            var reservedClaimsInList = parsedClaims
                .Where(p => Constants.ReservedClaims.Contains(p.BaseName))
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

            // Validate the caller's original claim tree before selective
            // disclosure processing can remove a reserved member from it.
            foreach (var claim in claims)
            {
                // A caller must never choose disclosure digests for the issuer
                // to sign. Otherwise they can later reveal arbitrary claims
                // that the issuer never selected for disclosure.
                if (claim.Key is Constants.SD_CLAIM_NAME or "...")
                {
                    throw new ArgumentException(
                        $"The claim '{claim.Key}' is reserved for issuer-generated SD-JWT disclosure references.",
                        nameof(claims));
                }

                if (claim.Key == Constants.SD_ALG_CLAIM_NAME)
                {
                    throw new ArgumentException(
                        $"The claim '{Constants.SD_ALG_CLAIM_NAME}' is reserved for internal use and cannot be explicitly set. " +
                        "The hash algorithm is specified via the hashAlgorithm parameter.",
                        nameof(claims));
                }

                ValidateRegisteredClaimRepresentation(claim.Key, claim.Value);
                ValidateNoUntrustedSdControlMembers(claim.Value, claim.Key);
            }

            // Normalize to case-sensitive JSON names even if the caller supplied
            // a dictionary with a case-insensitive comparer. Otherwise a
            // case-mismatched selector could pass validation while leaving
            // the original claim permanently disclosed in the signed token.
            var modifiedClaims = new Dictionary<string, object>(claims, StringComparer.Ordinal);

            // A requested top-level disclosure policy must be applied in full.
            // Missing simple claims and array bases were previously ignored,
            // allowing the issuer to sign a credential without the requested
            // redaction. Nested paths have their own structural validation.
            foreach (var claimPath in parsedClaims)
            {
                if (!claimPath.IsNested && !modifiedClaims.ContainsKey(claimPath.BaseName))
                {
                    throw new ArgumentException(
                        $"Cannot selectively disclose '{claimPath.OriginalSpec}': claim '{claimPath.BaseName}' does not exist.",
                        nameof(selectivelyDisclosableClaims));
                }
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
                    _ = arrayElementsToDisclose[claimPath.BaseName].Add(claimPath.ArrayIndex!.Value);
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

            // Redact nested claims and build objects with _sd arrays before wrapping parents.
            // The generated default belongs to the issued payload only.
            if (!hasExplicitExpiration)
            {
                modifiedClaims["exp"] = expClaim!;
            }

            if (nestedClaims.Count > 0)
            {
                var nestedProcessor = new NestedClaimProcessor(_disclosureGenerator, _digestCalculator);
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
                // Validated above: the selected array base must exist.
                var arrayValue = claims[arrayClaimName];

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
                        var disclosure = _disclosureGenerator.GenerateArrayElementDisclosure(elementValue);
                        disclosures.Add(disclosure);

                        // The array placeholder is the sole signed reference to this
                        // Disclosure (RFC 9901). Mirroring its digest into the
                        // top-level _sd array would create a forbidden duplicate.
                        var digest = _digestCalculator.ComputeDigest(disclosure, hashAlgorithm);

                        // Replace element with placeholder
                        newArray.Add(new Dictionary<string, string>
                    {
                        { "...", digest }
                    });
                    }
                    else
                    {
                        // Keep an independent JSON value without a reflection-based roundtrip.
                        // Preserve the existing JSON null -> CLR null payload representation.
                        var elementValue = arrayElement[i];
                        newArray.Add(elementValue.ValueKind == JsonValueKind.Null ? null! : elementValue.Clone());
                    }
                }

                // Replace the original array with the modified one
                modifiedClaims[arrayClaimName] = newArray;
            }

            // Wrap fully selective parent claims only after redacting their nested children
            foreach (var claimPath in simpleTopLevelClaims)
            {
                if (modifiedClaims.TryGetValue(claimPath.BaseName, out var claimValue))
                {
                    // Convert claim value to JsonElement
                    // Suppression: This is at the public API boundary where users provide arbitrary claim values.
                    // The library's internal processing is fully AOT-compatible (uses Utf8JsonWriter).
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement at API boundary
                    var jsonElement = JsonSerializer.SerializeToElement(claimValue);
#pragma warning restore IL2026, IL3050

                    // Generate disclosure
                    var disclosure = _disclosureGenerator.GenerateDisclosure(claimPath.BaseName, jsonElement);
                    disclosures.Add(disclosure);

                    // Compute digest
                    var digest = _digestCalculator.ComputeDigest(disclosure, hashAlgorithm);
                    digests.Add(digest);
                }
            }

            // Add decoy digests for privacy protection if requested
            // Per SD-JWT spec section 4.2.5: "The use of decoy digests is RECOMMENDED when the
            // number of claims (or the existence of particular claims) can be a side-channel
            // disclosing information about the End-User."
            if (decoyDigestCount > 0)
            {
                var _decoyGenerator = new DecoyDigestGenerator(_digestCalculator);
                var decoyDigests = _decoyGenerator.GenerateDecoyDigests(decoyDigestCount, hashAlgorithm);
                digests = _decoyGenerator.InterleaveDecoys(digests, decoyDigests);
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
                    payload[claim.Key] = claim.Value;
                }
            }

            // Add SD-JWT specific claims
            if (digests.Count > 0)
            {
                payload[Constants.SD_CLAIM_NAME] = digests;
            }

            payload[Constants.SD_ALG_CLAIM_NAME] = Constants.HashAlgorithmNames[hashAlgorithm];

            // Add cnf claim if holder public key is provided (for key binding)
            // Per RFC 7800 and SD-JWT spec section 4.3, use proper JWK format
            if (holderPublicKey != null)
            {
                var jwk = _ecPublicKeyConverter.ToJwk(holderPublicKey);
                payload["cnf"] = new Dictionary<string, object>
            {
                { "jwk", jwk }
            };
            }

            // Step 3: Create JWT using the specified signature algorithm
            var jwt = _jwtSigner.CreateJwt(payload, signingKey, signatureAlgorithm, keyId);

            // Step 4: Compute claim path mapping for presentation performance optimization
            // This caches the mapping at issuance time to avoid recomputation on every presentation
            var claimPathMapper = new DisclosureClaimPathMapper(_digestCalculator, new DisclosureParser());

            // Create temporary SdJwt to compute the mapping
            var tempSdJwt = new SdJwt(jwt, disclosures, hashAlgorithm);
            var claimPathMapping = claimPathMapper.BuildClaimPathMapping(tempSdJwt);

            // Step 5: Create final SdJwt object with cached mapping
            var sdJwt = new SdJwt(jwt, disclosures, hashAlgorithm, null, claimPathMapping);

            return sdJwt;
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Refuse registered JWT claims whose JSON shapes are invalid before
    /// signing. Otherwise the issuer can mint a token that this library's
    /// own verifier (and RFC 7519 conforming consumers) must reject.
    /// </summary>
    private static void ValidateRegisteredClaimRepresentation(string claimName, object? claimValue)
    {
        if (claimName is not ("iss" or "sub" or "jti" or "aud" or "nbf" or "iat"))
        {
            return;
        }

        // Common primitive claims already have their exact wire representation,
        // so avoid an extra JSON serialization in the issuance hot path.
        if (claimValue is string && (claimName is "iss" or "sub" or "jti" or "aud"))
        {
            return;
        }

        if (claimName is "nbf" or "iat")
        {
            if (claimValue is int)
            {
                return; // Every Int32 second is in the supported NumericDate range.
            }

            if (claimValue is long seconds &&
                seconds >= DateTimeOffset.MinValue.ToUnixTimeSeconds() &&
                seconds <= DateTimeOffset.MaxValue.ToUnixTimeSeconds())
            {
                return;
            }
        }

        // Examine what the signer actually writes, not JsonSerializer's
        // representation of the CLR value. JwtSigner supports values such as
        // multidimensional arrays that JsonSerializer cannot serialize.
        using var document = JwtSigner.SerializeClaimValueDocument(claimValue);
        var element = document.RootElement;

        var valid = claimName switch
        {
            "iss" or "sub" or "jti" => element.ValueKind == JsonValueKind.String,
            "aud" => HasValidAudienceShape(element),
            "nbf" or "iat" => NumericDateParser.TryParseUnixTicks(element, out _),
            _ => true
        };

        if (!valid)
        {
            throw new ArgumentException(
                $"The '{claimName}' claim has an invalid RFC 7519 JSON representation.",
                "claims");
        }
    }

    private static bool HasValidAudienceShape(JsonElement audience)
    {
        if (audience.ValueKind == JsonValueKind.String)
        {
            return true;
        }

        if (audience.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        // A single valid audience must not hide a malformed entry elsewhere
        // in a signed array. Every value must be a string.
        foreach (var value in audience.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Rejects caller-supplied SD-JWT control members before the issuer
    /// constructs its own disclosure digests and array placeholders.
    /// </summary>
    private const int MAX_CLAIM_VALIDATION_DEPTH = 64;

    private static void ValidateNoUntrustedSdControlMembers(object? value, string claimPath, int depth = 0)
    {
        if (value is null)
        {
            return;
        }

        // Bound runtime graph traversal to the serializer's default JSON depth.
        // Cyclic dictionaries/lists must cause a catchable error, not stack overflow.
        if (depth > MAX_CLAIM_VALIDATION_DEPTH)
        {
            throw new ArgumentException("Claim nesting exceeds the supported JSON depth.", nameof(value));
        }

        // JwtSigner.WriteValue serializes the public Digest model as an
        // array-element disclosure placeholder {"...": digest.Value}.
        // JsonSerializer.SerializeToElement(digest) instead exposes Value and
        // Algorithm properties, so inspecting its JSON shape misses this case.
        if (value is Digest)
        {
            throw new ArgumentException(
                $"The claim at '{claimPath}' contains a caller-supplied Digest; only the issuer may generate disclosure placeholders.",
                nameof(value));
        }

        // Inspect the JSON representation, not only Dictionary<string, object>.
        // Callers can supply anonymous objects, JsonElement, records, dictionaries
        // with different value types, or arrays containing any of those.
        if (value is JsonElement jsonElement)
        {
            ValidateNoUntrustedSdControlMembersElement(jsonElement, claimPath, depth);
            return;
        }

        // A string is IEnumerable<char>, but is a JSON scalar. Skip
        // per-character traversal, allocations and redundant serialization.
        if (value is string || value is decimal || value.GetType().IsPrimitive || value.GetType().IsEnum)
        {
            return;
        }

        // Keep common dictionaries and arrays on the no-serialization path.
        // Non-generic IDictionary also covers Dictionary<string, string>.
        if (value is System.Collections.IDictionary dictionary)
        {
            foreach (System.Collections.DictionaryEntry entry in dictionary)
            {
                if (entry.Key is string propertyName)
                {
                    ValidateReservedSdControlName(propertyName, claimPath);
                    ValidateNoUntrustedSdControlMembers(entry.Value, $"{claimPath}.{propertyName}", depth + 1);
                }
            }

            return;
        }

        if (value is System.Collections.IList list)
        {
            // Multidimensional arrays implement IList but their single-index
            // indexer throws. Foreach preserves JwtSigner's array traversal.
            var index = 0;
            foreach (var item in list)
            {
                ValidateNoUntrustedSdControlMembers(item, $"{claimPath}[{index}]", depth + 1);
                index++;
            }

            return;
        }

        if (value is System.Collections.IEnumerable enumerable)
        {
            // JwtSigner enumerates runtime values, even when a collection
            // declares its element type as IEnumerable. Inspect those actual
            // values rather than only their declared serializer contracts.
            var index = 0;
            foreach (var item in enumerable)
            {
                ValidateNoUntrustedSdControlMembers(item, $"{claimPath}[{index}]", depth + 1);
                index++;
            }

            // Immutable/read-only dictionaries may expose only an enumerable
            // interface; their JSON representation can also contain property
            // names that enumeration alone would miss.
#pragma warning disable IL2026, IL3050 // Public API accepts arbitrary claim values
            var collectionJson = JsonSerializer.SerializeToElement(value);
#pragma warning restore IL2026, IL3050
            ValidateNoUntrustedSdControlMembersElement(collectionJson, claimPath, depth);
            return;
        }

        // For arbitrary serializable objects (including anonymous types and
        // immutable dictionaries), inspect the same JSON property names that
        // would appear in the signed JWT rather than reflecting CLR fields.
#pragma warning disable IL2026, IL3050 // Public API accepts arbitrary claim values
        var serialized = JsonSerializer.SerializeToElement(value);
#pragma warning restore IL2026, IL3050
        ValidateNoUntrustedSdControlMembersElement(serialized, claimPath, depth);
    }

    private static void ValidateNoUntrustedSdControlMembersElement(JsonElement value, string claimPath, int depth)
    {
        if (depth > MAX_CLAIM_VALIDATION_DEPTH)
        {
            throw new ArgumentException("Claim nesting exceeds the supported JSON depth.", nameof(value));
        }

        if (value.ValueKind == JsonValueKind.Object)
        {
            // JsonElement preserves repeated names, including escaped equivalents.
            // Refuse ambiguous objects before the issuer authenticates their bytes:
            // the verifier already rejects them and consumers may disagree on the
            // first/last value. Check each nested object, including array entries.
            if (JsonObjectMemberGuard.HasInvalidOrDuplicateNames(value))
            {
                throw new ArgumentException(
                    $"The JSON object at '{claimPath}' contains duplicate or invalid member names.",
                    nameof(value));
            }

            foreach (var property in value.EnumerateObject())
            {
                ValidateReservedSdControlName(property.Name, claimPath);
                ValidateNoUntrustedSdControlMembersElement(property.Value, $"{claimPath}.{property.Name}", depth + 1);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in value.EnumerateArray())
            {
                ValidateNoUntrustedSdControlMembersElement(item, $"{claimPath}[{index}]", depth + 1);
                index++;
            }
        }
    }

    private static void ValidateReservedSdControlName(string propertyName, string claimPath)
    {
        if (propertyName is Constants.SD_CLAIM_NAME or "...")
        {
            throw new ArgumentException(
                $"The claim '{propertyName}' at path '{claimPath}.{propertyName}' is reserved for issuer-generated SD-JWT disclosure references.",
                nameof(propertyName));
        }

        if (propertyName == Constants.SD_ALG_CLAIM_NAME)
        {
            throw new ArgumentException(
                $"The claim '{Constants.SD_ALG_CLAIM_NAME}' was found in nested object at path '{claimPath}.{propertyName}'. " +
                "Per SD-JWT specification section 4.2.3, _sd_alg MUST appear at the top level of the SD-JWT payload " +
                "and MUST NOT be used in any object nested within the payload.",
                nameof(propertyName));
        }
    }
}
