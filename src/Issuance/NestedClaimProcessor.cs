using HeroSdJwt.Common;
using HeroSdJwt.Core;
using System.Text.Json;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Processes nested claims and builds objects with selective disclosure at multiple levels.
/// Supports nested _sd arrays within objects per SD-JWT spec.
/// </summary>
internal class NestedClaimProcessor
{
    private readonly DisclosureGenerator _disclosureGenerator;
    private readonly DigestCalculator _digestCalculator;

    public NestedClaimProcessor(DisclosureGenerator disclosureGenerator, DigestCalculator digestCalculator)
    {
        _disclosureGenerator = disclosureGenerator;
        _digestCalculator = digestCalculator;
    }

    /// <summary>
    /// Processes nested claims and returns modified claims with _sd arrays at appropriate levels.
    /// </summary>
    /// <param name="claims">Original claims dictionary</param>
    /// <param name="nestedClaimPaths">Parsed paths for nested claims (e.g., "address.city")</param>
    /// <param name="hashAlgorithm">Hash algorithm for digests</param>
    /// <param name="disclosures">Output list for generated disclosures</param>
    /// <param name="digests">Output list for computed digests (only top-level)</param>
    /// <returns>Modified claims dictionary with nested _sd arrays</returns>
    public Dictionary<string, object> ProcessNestedClaims(
        Dictionary<string, object> claims,
        List<ClaimPath> nestedClaimPaths,
        HashAlgorithm hashAlgorithm,
        List<string> disclosures,
        List<string> digests)
    {
        if (nestedClaimPaths.Count == 0)
        {
            return claims;
        }

        var modifiedClaims = new Dictionary<string, object>(claims);

        // Group nested paths by base name
        var groupedByBase = nestedClaimPaths
            .GroupBy(p => p.BaseName)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var (baseName, paths) in groupedByBase)
        {
            if (!claims.TryGetValue(baseName, out var baseValue))
            {
                continue; // Base claim doesn't exist
            }

            // Convert to JsonElement for processing
            var baseElement = JsonSerializer.SerializeToElement(baseValue);

            if (baseElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException(
                    $"Claim '{baseName}' is specified with nested property syntax (e.g., '{baseName}.property'), " +
                    "but the actual value is not an object.",
                    nameof(nestedClaimPaths));
            }

            // Build modified object with _sd array
            var modifiedObject = BuildObjectWithSelectiveDisclosure(
                baseElement,
                paths,
                hashAlgorithm,
                disclosures);

            modifiedClaims[baseName] = modifiedObject;
        }

        return modifiedClaims;
    }

    /// <summary>
    /// Builds an object with selective disclosure for specified nested paths.
    /// Adds _sd array to the object containing digests for selectively disclosable properties.
    /// Recursively processes multi-level nesting (e.g., "address.geo.lat").
    /// </summary>
    private Dictionary<string, object> BuildObjectWithSelectiveDisclosure(
        JsonElement originalObject,
        List<ClaimPath> nestedPaths,
        HashAlgorithm hashAlgorithm,
        List<string> disclosures)
    {
        var result = new Dictionary<string, object>();
        var sdDigests = new List<string>();

        // Get all properties from the original object
        var allProperties = new Dictionary<string, JsonElement>();
        foreach (var property in originalObject.EnumerateObject())
        {
            allProperties[property.Name] = property.Value;
        }

        // Group paths by first nested level (e.g., "address.geo.lat" -> "geo")
        var pathsByProperty = new Dictionary<string, List<ClaimPath>>();
        foreach (var path in nestedPaths)
        {
            var firstNestedProperty = path.PathComponents[1];
            if (!pathsByProperty.ContainsKey(firstNestedProperty))
            {
                pathsByProperty[firstNestedProperty] = new List<ClaimPath>();
            }
            pathsByProperty[firstNestedProperty].Add(path);
        }

        foreach (var (propertyName, propertyValue) in allProperties)
        {
            if (pathsByProperty.TryGetValue(propertyName, out var pathsForThisProperty))
            {
                // This property has selective disclosure requirements
                // Check if there are deeper nested paths (e.g., "address.geo.lat" has depth > 2)
                var deeperPaths = pathsForThisProperty
                    .Where(p => p.PathComponents.Length > 2)
                    .ToList();

                JsonElement valueToDisclose;

                if (deeperPaths.Any() && propertyValue.ValueKind == JsonValueKind.Object)
                {
                    // Need to recursively process this object for deeper nesting
                    // Create new paths with first component removed (e.g., "address.geo.lat" -> "geo.lat")
                    var shiftedPaths = deeperPaths.Select(p =>
                    {
                        var newComponents = p.PathComponents.Skip(1).ToArray();
                        var newOriginalSpec = string.Join(".", newComponents);
                        return ClaimPath.Parse(newOriginalSpec);
                    }).ToList();

                    // Recursively build the nested object
                    var nestedObject = BuildObjectWithSelectiveDisclosure(
                        propertyValue,
                        shiftedPaths,
                        hashAlgorithm,
                        disclosures);

                    // Serialize the nested object back to JsonElement
                    valueToDisclose = JsonSerializer.SerializeToElement(nestedObject);
                }
                else
                {
                    // Leaf property or simple value - disclose as-is
                    valueToDisclose = propertyValue;
                }

                // Generate disclosure for this property (with potentially modified nested value)
                var disclosure = _disclosureGenerator.GenerateDisclosure(propertyName, valueToDisclose);
                disclosures.Add(disclosure);

                // Compute digest
                var digest = _digestCalculator.ComputeDigest(disclosure, hashAlgorithm);
                sdDigests.Add(digest);

                // Don't add this property to the result object - it's now hidden in disclosure
            }
            else
            {
                // Non-selective property - include as-is
                var nativeValue = JsonSerializer.Deserialize<object>(propertyValue.GetRawText());
                result[propertyName] = nativeValue!;
            }
        }

        // Add _sd array if there are selective disclosures
        if (sdDigests.Count > 0)
        {
            result["_sd"] = sdDigests;
        }

        return result;
    }
}
