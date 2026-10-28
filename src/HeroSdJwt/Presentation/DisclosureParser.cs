using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Parses disclosure documents from base64url-encoded format.
/// </summary>
public class DisclosureParser : IDisclosureParser
{

    /// <summary>
    /// Parses a base64url-encoded disclosure and extracts the disclosure information.
    /// Supports both formats:
    /// - Object property: Base64url(JSON([salt, claim_name, claim_value])) - 3 elements
    /// - Array element: Base64url(JSON([salt, claim_value])) - 2 elements
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The Disclosure object.</returns>
    public Disclosure Parse(string base64UrlDisclosure)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDisclosure);

        // Decode from base64url to JSON
        var json = Base64UrlEncoder.DecodeString(base64UrlDisclosure);

        // Parse JSON array
        using var document = JsonDocument.Parse(json);
        var jsonArray = document.RootElement;

        if (jsonArray.ValueKind != JsonValueKind.Array)
        {
            throw new MalformedDisclosureException(
                "Disclosure must be a JSON array");
        }

        var arrayLength = jsonArray.GetArrayLength();

        // Per SD-JWT spec section 4.2.4:
        // - 3-element array: [salt, claim_name, claim_value] for object properties
        // - 2-element array: [salt, claim_value] for array elements
        if (arrayLength is not 2 and not 3)
        {
            throw new MalformedDisclosureException(
                "Disclosure must be a JSON array with 2 elements (array element) or 3 elements (object property)");
        }

        var saltElement = jsonArray[0];
        if (saltElement.ValueKind == JsonValueKind.Null)
        {
            throw new MalformedDisclosureException("Disclosure salt cannot be null");
        }

        if (saltElement.ValueKind != JsonValueKind.String)
        {
            throw new MalformedDisclosureException("Disclosure salt must be a string");
        }

        var salt = saltElement.GetString();
        if (string.IsNullOrWhiteSpace(salt))
        {
            throw new MalformedDisclosureException("Disclosure salt cannot be empty or whitespace");
        }

        if (arrayLength == 2)
        {
            // Array element disclosure: [salt, claim_value]
            var claimValue = jsonArray[1];
            return new Disclosure(salt, claimValue.Clone());
        }
        else
        {
            // Object property disclosure: [salt, claim_name, claim_value]
            var claimNameElement = jsonArray[1];
            if (claimNameElement.ValueKind == JsonValueKind.Null)
            {
                throw new MalformedDisclosureException("Disclosure claim name cannot be null");
            }

            if (claimNameElement.ValueKind != JsonValueKind.String)
            {
                throw new MalformedDisclosureException("Disclosure claim name must be a string");
            }

            var claimName = claimNameElement.GetString();
            if (string.IsNullOrWhiteSpace(claimName))
            {
                throw new MalformedDisclosureException("Disclosure claim name cannot be empty or whitespace");
            }

            // RFC 9901 Sections 4.1.1 and 4.2.1: _sd_alg is an issuer JWT
            // top-level control, while _sd and ... are digest control members.
            if (claimName is "_sd" or "..." or "_sd_alg")
            {
                throw new MalformedDisclosureException("Disclosure claim name is reserved");
            }

            var claimValue = jsonArray[2];
            return new Disclosure(salt, claimName, claimValue.Clone());
        }
    }

    /// <summary>
    /// Extracts just the claim name from a disclosure without full parsing.
    /// Returns null for array element disclosures (2-element format).
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The claim name, or null for array elements.</returns>
    public string? GetClaimName(string base64UrlDisclosure)
    {
        var disclosure = Parse(base64UrlDisclosure);
        return disclosure.ClaimName;
    }
}
