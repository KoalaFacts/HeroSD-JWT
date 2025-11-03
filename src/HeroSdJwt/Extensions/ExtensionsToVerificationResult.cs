using System.Text.Json;
using System.Text.Json.Nodes;
using HeroSdJwt.Models;

// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure - intentional for extension methods
namespace HeroSdJwt.Extensions;
#pragma warning restore IDE0130

/// <summary>
/// Extension methods for <see cref="VerificationResult"/> providing claim reconstruction capabilities.
/// </summary>
public static class ExtensionsToVerificationResult
{
    /// <summary>
    /// Reconstructs an array from disclosed array element claims.
    /// </summary>
    /// <param name="result">The verification result containing disclosed claims. Must not be null and IsValid must be true.</param>
    /// <param name="claimName">The base name of the array claim (e.g., "degrees" for "degrees[0]", "degrees[1]"). Must not be null or whitespace.</param>
    /// <returns>
    /// A JsonElement of type JsonValueKind.Array containing disclosed elements at their original indices.
    /// Sparse arrays use null for non-disclosed indices.
    /// Returns null if the claim name does not exist in DisclosedClaims.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when result is null.</exception>
    /// <exception cref="ArgumentException">Thrown when claimName is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when result.IsValid is false.</exception>
    public static JsonElement? GetDisclosedArray(this VerificationResult result, string claimName)
    {
        ArgumentNullException.ThrowIfNull(result, nameof(result));

        if (string.IsNullOrWhiteSpace(claimName))
        {
            throw new ArgumentException("Claim name cannot be null or whitespace.", nameof(claimName));
        }

        if (!result.IsValid)
        {
            throw new InvalidOperationException("Cannot reconstruct claims from an invalid verification result. IsValid must be true.");
        }

        // Find all array element claims for this base name
        var arrayElements = new SortedDictionary<int, JsonElement>();

        foreach (var (key, value) in result.DisclosedClaims)
        {
            var path = ClaimPath.Parse(key);

            if (path.BaseName == claimName && path.IsArrayElement)
            {
                arrayElements[path.ArrayIndex!.Value] = value;
            }
        }

        // If no array elements found, return null
        if (arrayElements.Count == 0)
        {
            return null;
        }

        // Build sparse array with nulls for missing indices
        var maxIndex = arrayElements.Keys.Max();
        var jsonArray = new JsonArray();

        for (int i = 0; i <= maxIndex; i++)
        {
            if (arrayElements.TryGetValue(i, out var element))
            {
                jsonArray.Add(JsonNode.Parse(element.GetRawText()));
            }
            else
            {
                jsonArray.Add(null);
            }
        }

        // Convert JsonArray to JsonElement
        var jsonString = jsonArray.ToJsonString();
        return JsonDocument.Parse(jsonString).RootElement.Clone();
    }

    /// <summary>
    /// Reconstructs a hierarchical object from disclosed nested property claims.
    /// </summary>
    /// <param name="result">The verification result containing disclosed claims. Must not be null and IsValid must be true.</param>
    /// <param name="claimName">The base name of the object claim (e.g., "address" for "address.street", "address.city"). Must not be null or whitespace.</param>
    /// <returns>
    /// A JsonElement of type JsonValueKind.Object containing disclosed properties in hierarchical structure.
    /// Nested paths are reconstructed as nested objects (e.g., "a.b.c" → { a: { b: { c: value } } }).
    /// Returns null if the claim name does not exist in DisclosedClaims.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when result is null.</exception>
    /// <exception cref="ArgumentException">Thrown when claimName is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when result.IsValid is false.</exception>
    public static JsonElement? GetDisclosedObject(this VerificationResult result, string claimName)
    {
        ArgumentNullException.ThrowIfNull(result, nameof(result));

        if (string.IsNullOrWhiteSpace(claimName))
        {
            throw new ArgumentException("Claim name cannot be null or whitespace.", nameof(claimName));
        }

        if (!result.IsValid)
        {
            throw new InvalidOperationException("Cannot reconstruct claims from an invalid verification result. IsValid must be true.");
        }

        // Find all nested property claims for this base name
        var nestedProperties = new List<(string[] path, JsonElement value)>();

        foreach (var (key, value) in result.DisclosedClaims)
        {
            var path = ClaimPath.Parse(key);

            if (path.BaseName == claimName && path.IsNested)
            {
                nestedProperties.Add((path.PathComponents, value));
            }
        }

        // If no nested properties found, return null
        if (nestedProperties.Count == 0)
        {
            return null;
        }

        // Build hierarchical object using bottom-up tree construction
        var rootObject = new JsonObject();

        foreach (var (pathComponents, value) in nestedProperties)
        {
            // Skip the base name (first component) since we're building the object under it
            var relativePath = pathComponents.Skip(1).ToArray();

            // Navigate/create nested structure
            JsonObject currentObject = rootObject;

            for (int i = 0; i < relativePath.Length - 1; i++)
            {
                var component = relativePath[i];

                if (!currentObject.ContainsKey(component))
                {
                    currentObject[component] = new JsonObject();
                }

                currentObject = (JsonObject)currentObject[component]!;
            }

            // Set the final value
            var finalKey = relativePath[^1];
            currentObject[finalKey] = JsonNode.Parse(value.GetRawText());
        }

        // Convert JsonObject to JsonElement
        var jsonString = rootObject.ToJsonString();
        return JsonDocument.Parse(jsonString).RootElement.Clone();
    }

    /// <summary>
    /// Discovers which claims in the verification result can be reconstructed as arrays or objects.
    /// </summary>
    /// <param name="result">The verification result containing disclosed claims. Must not be null and IsValid must be true.</param>
    /// <returns>
    /// A dictionary mapping base claim names to their reconstruction type (Array or Object).
    /// Only includes claims with array or nested structure (excludes simple claims).
    /// Returns an empty dictionary if no reconstructible claims found.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when result is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when result.IsValid is false.</exception>
    public static IReadOnlyDictionary<string, ReconstructibleClaimType> GetReconstructibleClaims(this VerificationResult result)
    {
        ArgumentNullException.ThrowIfNull(result, nameof(result));

        if (!result.IsValid)
        {
            throw new InvalidOperationException("Cannot discover claims from an invalid verification result. IsValid must be true.");
        }

        var reconstructible = new Dictionary<string, ReconstructibleClaimType>();

        foreach (var (key, _) in result.DisclosedClaims)
        {
            var path = ClaimPath.Parse(key);

            // Skip if we've already categorized this base name
            if (reconstructible.ContainsKey(path.BaseName))
            {
                continue;
            }

            // Categorize based on claim type
            if (path.IsArrayElement)
            {
                reconstructible[path.BaseName] = ReconstructibleClaimType.Array;
            }
            else if (path.IsNested)
            {
                reconstructible[path.BaseName] = ReconstructibleClaimType.Object;
            }
            // else: simple claim, exclude from results
        }

        return reconstructible;
    }
}
