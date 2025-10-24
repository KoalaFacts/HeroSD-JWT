using System.Text.Json;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Interface for generating disclosure documents with cryptographically secure salts.
/// </summary>
public interface IDisclosureGenerator
{
    /// <summary>
    /// Generates a base64url-encoded disclosure for an object property (3-element format).
    /// </summary>
    /// <param name="claimName">The name of the claim.</param>
    /// <param name="claimValue">The value of the claim.</param>
    /// <returns>Base64url-encoded disclosure string.</returns>
    string GenerateDisclosure(string claimName, JsonElement claimValue);

    /// <summary>
    /// Generates a base64url-encoded disclosure for an array element (2-element format).
    /// </summary>
    /// <param name="claimValue">The value of the array element.</param>
    /// <returns>Base64url-encoded disclosure string.</returns>
    string GenerateArrayElementDisclosure(JsonElement claimValue);
}
