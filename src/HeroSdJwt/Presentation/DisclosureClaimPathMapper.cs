using System.Text.Json;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Maps claim paths (e.g., "address.street") to their corresponding disclosures
/// by analyzing the JWT structure and matching disclosure digests.
/// Per SD-JWT spec, the holder must maintain this mapping for presentation creation.
/// </summary>
public class DisclosureClaimPathMapper : IDisclosureClaimPathMapper
{
    private readonly IDigestCalculator digestCalculator;
    private readonly IDisclosureParser disclosureParser;

    // Security: Maximum nesting depth to prevent stack overflow attacks
    private const int maxNestingDepth = 10;

    /// <summary>
    /// Initializes a new instance of the <see cref="DisclosureClaimPathMapper"/> class.
    /// </summary>
    public DisclosureClaimPathMapper()
        : this(new DigestCalculator(), new DisclosureParser())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DisclosureClaimPathMapper"/> class with dependencies.
    /// </summary>
    public DisclosureClaimPathMapper(IDigestCalculator digestCalculator, IDisclosureParser disclosureParser)
    {
        this.digestCalculator = digestCalculator ?? throw new ArgumentNullException(nameof(digestCalculator));
        this.disclosureParser = disclosureParser ?? throw new ArgumentNullException(nameof(disclosureParser));
    }

    /// <summary>
    /// Builds a mapping from user-friendly claim paths to disclosure indices.
    /// This enables ToPresentation() to work with nested and array element claims.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT containing JWT and disclosures.</param>
    /// <returns>Dictionary mapping claim paths to disclosure indices.</returns>
    public Dictionary<string, int> BuildClaimPathMapping(SdJwt sdJwt)
    {
        var mapping = new Dictionary<string, int>();

        // Parse JWT payload to understand structure
        var jwtParts = sdJwt.Jwt.Split('.');
        if (jwtParts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT format");
        }

        var payloadJson = Base64UrlEncoder.DecodeString(jwtParts[1]);
        var payload = JsonDocument.Parse(payloadJson).RootElement;

        // Build digest-to-disclosure-index map
        var digestToIndex = new Dictionary<string, int>();
        for (int i = 0; i < sdJwt.Disclosures.Count; i++)
        {
            var digest = digestCalculator.ComputeDigest(sdJwt.Disclosures[i], sdJwt.HashAlgorithm);
            digestToIndex[digest] = i;
        }

        // Recursively process payload to find all _sd arrays and map them
        ProcessElement(payload, "", digestToIndex, sdJwt.Disclosures, mapping);

        return mapping;
    }

    /// <summary>
    /// Recursively processes a JSON element to find _sd arrays and build path mappings.
    /// </summary>
    private void ProcessElement(
        JsonElement element,
        string currentPath,
        Dictionary<string, int> digestToIndex,
        IReadOnlyList<string> disclosures,
        Dictionary<string, int> mapping)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            ProcessObject(element, currentPath, digestToIndex, disclosures, mapping);
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            ProcessArray(element, currentPath, digestToIndex, disclosures, mapping);
        }
    }

    /// <summary>
    /// Processes a JSON object to find _sd array and map nested claims.
    /// </summary>
    private void ProcessObject(
        JsonElement obj,
        string currentPath,
        Dictionary<string, int> digestToIndex,
        IReadOnlyList<string> disclosures,
        Dictionary<string, int> mapping)
    {
        List<string>? sdDigests = null;

        foreach (var property in obj.EnumerateObject())
        {
            if (property.Name == "_sd" && property.Value.ValueKind == JsonValueKind.Array)
            {
                // Found _sd array - collect digests
                sdDigests = new List<string>();
                foreach (var digest in property.Value.EnumerateArray())
                {
                    if (digest.ValueKind == JsonValueKind.String)
                    {
                        sdDigests.Add(digest.GetString()!);
                    }
                }
            }
            else if (property.Name != "_sd_alg") // Skip metadata
            {
                // Recursively process nested structures
                var newPath = string.IsNullOrEmpty(currentPath)
                    ? property.Name
                    : $"{currentPath}.{property.Name}";
                ProcessElement(property.Value, newPath, digestToIndex, disclosures, mapping);
            }
        }

        // Process _sd array if found at this level
        if (sdDigests != null)
        {
            foreach (var digest in sdDigests)
            {
                if (digestToIndex.TryGetValue(digest, out var disclosureIndex))
                {
                    // Parse the disclosure to get the claim name and value
                    var disclosure = disclosureParser.Parse(disclosures[disclosureIndex]);
                    if (disclosure.ClaimName != null)
                    {
                        // Build the full path: currentPath + claim name
                        var fullPath = string.IsNullOrEmpty(currentPath)
                            ? disclosure.ClaimName
                            : $"{currentPath}.{disclosure.ClaimName}";

                        // Add to mapping (including intermediate objects - they're needed for presentations)
                        mapping[fullPath] = disclosureIndex;

                        // Recursively process the disclosure value if it's an object or array
                        // This handles nested _sd arrays within selectively disclosable claims
                        ProcessElement(disclosure.ClaimValue, fullPath, digestToIndex, disclosures, mapping);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Processes a JSON array to find array element placeholders.
    /// </summary>
    private void ProcessArray(
        JsonElement array,
        string currentPath,
        Dictionary<string, int> digestToIndex,
        IReadOnlyList<string> disclosures,
        Dictionary<string, int> mapping)
    {
        var index = 0;
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object &&
                item.TryGetProperty("...", out var digestProp) &&
                digestProp.ValueKind == JsonValueKind.String)
            {
                // This is an array element placeholder
                var digest = digestProp.GetString()!;
                if (digestToIndex.TryGetValue(digest, out var disclosureIndex))
                {
                    // Array element path: "claimName[index]"
                    var arrayPath = $"{currentPath}[{index}]";
                    mapping[arrayPath] = disclosureIndex;

                    // Recursively process the array element value
                    var disclosure = disclosureParser.Parse(disclosures[disclosureIndex]);
                    ProcessElement(disclosure.ClaimValue, arrayPath, digestToIndex, disclosures, mapping);
                }
            }
            else
            {
                // Recursively process nested elements
                var newPath = $"{currentPath}[{index}]";
                ProcessElement(item, newPath, digestToIndex, disclosures, mapping);
            }

            index++;
        }
    }
}
