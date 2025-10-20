using HeroSdJwt.Common;
using HeroSdJwt.Core;
using System.Text.Json;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Parses disclosure documents from base64url-encoded format.
/// </summary>
internal static class DisclosureParser
{
    /// <summary>
    /// Parses a base64url-encoded disclosure and extracts the disclosure information.
    /// Supports both formats:
    /// - Object property: Base64url(JSON([salt, claim_name, claim_value])) - 3 elements
    /// - Array element: Base64url(JSON([salt, claim_value])) - 2 elements
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The Disclosure object.</returns>
    public static Disclosure Parse(string base64UrlDisclosure)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDisclosure);

        // Decode from base64url to JSON
        var json = Base64UrlEncoder.DecodeString(base64UrlDisclosure);

        // Parse JSON array
        var jsonArray = JsonDocument.Parse(json).RootElement;

        if (jsonArray.ValueKind != JsonValueKind.Array)
        {
            throw new MalformedDisclosureException(
                "Disclosure must be a JSON array");
        }

        var arrayLength = jsonArray.GetArrayLength();

        // Per SD-JWT spec section 4.2.4:
        // - 3-element array: [salt, claim_name, claim_value] for object properties
        // - 2-element array: [salt, claim_value] for array elements
        if (arrayLength != 2 && arrayLength != 3)
        {
            throw new MalformedDisclosureException(
                "Disclosure must be a JSON array with 2 elements (array element) or 3 elements (object property)");
        }

        var salt = jsonArray[0].GetString()
            ?? throw new MalformedDisclosureException("Disclosure salt cannot be null");

        if (arrayLength == 2)
        {
            // Array element disclosure: [salt, claim_value]
            var claimValue = jsonArray[1];
            return new Disclosure(salt, claimValue);
        }
        else
        {
            // Object property disclosure: [salt, claim_name, claim_value]
            var claimName = jsonArray[1].GetString()
                ?? throw new MalformedDisclosureException("Disclosure claim name cannot be null");

            var claimValue = jsonArray[2];
            return new Disclosure(salt, claimName, claimValue);
        }
    }

    /// <summary>
    /// Extracts just the claim name from a disclosure without full parsing.
    /// Returns null for array element disclosures (2-element format).
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The claim name, or null for array elements.</returns>
    public static string? GetClaimName(string base64UrlDisclosure)
    {
        var disclosure = Parse(base64UrlDisclosure);
        return disclosure.ClaimName;
    }
}
