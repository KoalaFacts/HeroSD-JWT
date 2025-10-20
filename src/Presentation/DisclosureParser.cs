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
    /// Parses a base64url-encoded disclosure and extracts the claim name.
    /// Format: Base64url(JSON([salt, claim_name, claim_value]))
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The Disclosure object.</returns>
    public static Disclosure Parse(string base64UrlDisclosure)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDisclosure);

        // Decode from base64url to JSON
        var json = Base64UrlEncoder.DecodeString(base64UrlDisclosure);

        // Parse JSON array [salt, claim_name, claim_value]
        var jsonArray = JsonDocument.Parse(json).RootElement;

        if (jsonArray.ValueKind != JsonValueKind.Array || jsonArray.GetArrayLength() != 3)
        {
            throw new MalformedDisclosureException(
                "Disclosure must be a JSON array with exactly 3 elements");
        }

        var salt = jsonArray[0].GetString()
            ?? throw new MalformedDisclosureException("Disclosure salt cannot be null");

        var claimName = jsonArray[1].GetString()
            ?? throw new MalformedDisclosureException("Disclosure claim name cannot be null");

        var claimValue = jsonArray[2];

        return new Disclosure(salt, claimName, claimValue);
    }

    /// <summary>
    /// Extracts just the claim name from a disclosure without full parsing.
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The claim name.</returns>
    public static string GetClaimName(string base64UrlDisclosure)
    {
        var disclosure = Parse(base64UrlDisclosure);
        return disclosure.ClaimName;
    }
}
