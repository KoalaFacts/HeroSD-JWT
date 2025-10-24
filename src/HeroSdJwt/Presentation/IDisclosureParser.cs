using HeroSdJwt.Models;

namespace HeroSdJwt.Presentation;

/// <summary>
/// Interface for parsing disclosure documents from base64url-encoded format.
/// </summary>
public interface IDisclosureParser
{
    /// <summary>
    /// Parses a base64url-encoded disclosure and extracts the disclosure information.
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The Disclosure object.</returns>
    Disclosure Parse(string base64UrlDisclosure);

    /// <summary>
    /// Extracts just the claim name from a disclosure without full parsing.
    /// </summary>
    /// <param name="base64UrlDisclosure">The base64url-encoded disclosure.</param>
    /// <returns>The claim name, or null for array elements.</returns>
    string? GetClaimName(string base64UrlDisclosure);
}
