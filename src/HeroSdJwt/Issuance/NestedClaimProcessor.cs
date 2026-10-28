using HeroSdJwt.Models;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Processes nested claims and builds objects with selective disclosure at multiple levels.
/// Supports nested _sd arrays within objects per SD-JWT spec.
/// </summary>
internal class NestedClaimProcessor(IDisclosureGenerator disclosureGenerator, IDigestCalculator digestCalculator)
{
    private readonly IDisclosureGenerator _disclosureGenerator = disclosureGenerator;
    private readonly IDigestCalculator _digestCalculator = digestCalculator;

    // Security: Maximum nesting depth to prevent stack overflow attacks
    private const int MAX_NESTING_DEPTH = 10;


    /// <summary>
    /// Processes nested claims and returns modified claims with _sd arrays at appropriate levels.
    /// </summary>
    /// <param name="claims">Original claims dictionary</param>
    /// <param name="nestedClaimPaths">Parsed paths for nested claims (e.g., "address.city")</param>
    /// <param name="hashAlgorithm">Hash algorithm for digests</param>
    /// <param name="disclosures">Output list for generated disclosures</param>
    /// <returns>Modified claims dictionary with nested _sd arrays</returns>
    public Dictionary<string, object> ProcessNestedClaims(
        Dictionary<string, object> claims,
        List<ClaimPath> nestedClaimPaths,
        HashAlgorithm hashAlgorithm,
        List<string> disclosures)
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
                // Silently ignoring an explicitly requested path can cause an
                // issuer to return a credential with a different disclosure
                // policy than the caller intended.
                throw new ArgumentException(
                    $"Requested nested claim path '{paths[0].OriginalSpec}' has no base claim '{baseName}'.",
                    nameof(nestedClaimPaths));
            }

            // Convert to JsonElement for processing
            // Suppression: This is at the public API boundary where users provide arbitrary claim values.
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement at API boundary
            var baseElement = JsonSerializer.SerializeToElement(baseValue);
#pragma warning restore IL2026, IL3050

            if (baseElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException(
                    $"Claim '{baseName}' is specified with nested property syntax (e.g., '{baseName}.property'), " +
                    "but the actual value is not an object.",
                    nameof(nestedClaimPaths));
            }

            // Validate every requested path before generating disclosures.
            // If an intermediate value is a scalar/array or a leaf is absent,
            // the recursive builder would otherwise disclose its whole parent
            // while silently failing to protect the requested leaf.
            EnsureRequestedPathsExist(baseElement, paths);

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

    private static void EnsureRequestedPathsExist(JsonElement baseElement, IReadOnlyList<ClaimPath> paths)
    {
        foreach (var path in paths)
        {
            var element = baseElement;
            for (var index = 1; index < path.PathComponents.Length; index++)
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    throw new ArgumentException(
                        $"Cannot selectively disclose '{path.OriginalSpec}': " +
                        $"'{path.PathComponents[index - 1]}' is not an object.",
                        nameof(paths));
                }

                if (!element.TryGetProperty(path.PathComponents[index], out var next))
                {
                    throw new ArgumentException(
                        $"Cannot selectively disclose '{path.OriginalSpec}': " +
                        $"property '{path.PathComponents[index]}' does not exist.",
                        nameof(paths));
                }

                element = next;
            }
        }
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
        List<string> disclosures,
        int depth = 0)
    {
        // Security: Prevent stack overflow with deeply nested structures
        if (depth > MAX_NESTING_DEPTH)
        {
            throw new ArgumentException($"Maximum nesting depth of {MAX_NESTING_DEPTH} exceeded. This may indicate a malformed or malicious JSON structure.");
        }
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
                pathsByProperty[firstNestedProperty] = [];
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

                    // Recursively build the nested object (increment depth)
                    var nestedObject = BuildObjectWithSelectiveDisclosure(
                        propertyValue,
                        shiftedPaths,
                        hashAlgorithm,
                        disclosures,
                        depth + 1);

                    // Serialize the nested object back to JsonElement
                    // Suppression: Converting processed nested object back to JsonElement.
#pragma warning disable IL2026, IL3050 // JsonSerializer.SerializeToElement for internal processing
                    valueToDisclose = JsonSerializer.SerializeToElement(nestedObject);
#pragma warning restore IL2026, IL3050
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
                // Keep an independent JSON value without a reflection-based roundtrip.
                // Preserve the existing JSON null -> CLR null payload representation.
                result[propertyName] = propertyValue.ValueKind == JsonValueKind.Null ? null! : propertyValue.Clone();
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
