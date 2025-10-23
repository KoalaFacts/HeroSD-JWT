using HeroSdJwt.Common;
using HeroSdJwt.Core;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Generates disclosure documents with cryptographically secure salts.
/// Supports both object property and array element disclosures.
/// </summary>
public class DisclosureGenerator
{
    /// <summary>
    /// Generates a base64url-encoded disclosure for an object property (3-element format).
    /// Format: Base64url(JSON([salt, claim_name, claim_value]))
    /// AOT-compatible: Uses Disclosure.ToJson() with Utf8JsonWriter.
    /// </summary>
    /// <param name="claimName">The name of the claim.</param>
    /// <param name="claimValue">The value of the claim.</param>
    /// <returns>Base64url-encoded disclosure string.</returns>
    public string GenerateDisclosure(string claimName, JsonElement claimValue)
    {
        ArgumentNullException.ThrowIfNull(claimName);

        if (string.IsNullOrWhiteSpace(claimName))
        {
            throw new ArgumentException("Claim name cannot be empty or whitespace.", nameof(claimName));
        }

        // Generate cryptographically secure random salt (128 bits = 16 bytes minimum)
        var saltBytes = new byte[Constants.MinimumSaltLengthBytes];
        RandomNumberGenerator.Fill(saltBytes);

        // Convert salt to base64url
        var salt = Base64UrlEncoder.Encode(saltBytes);

        // Create disclosure and serialize to JSON using AOT-compatible method
        var disclosure = new Disclosure(salt, claimName, claimValue);
        var json = disclosure.ToJson();

        // Convert to base64url
        return Base64UrlEncoder.Encode(json);
    }

    /// <summary>
    /// Generates a base64url-encoded disclosure for an array element (2-element format).
    /// Format: Base64url(JSON([salt, claim_value]))
    /// Per SD-JWT spec section 4.2.4, array elements don't include a claim name.
    /// AOT-compatible: Uses Disclosure.ToJson() with Utf8JsonWriter.
    /// </summary>
    /// <param name="claimValue">The value of the array element.</param>
    /// <returns>Base64url-encoded disclosure string.</returns>
    public string GenerateArrayElementDisclosure(JsonElement claimValue)
    {
        // Generate cryptographically secure random salt (128 bits = 16 bytes minimum)
        var saltBytes = new byte[Constants.MinimumSaltLengthBytes];
        RandomNumberGenerator.Fill(saltBytes);

        // Convert salt to base64url
        var salt = Base64UrlEncoder.Encode(saltBytes);

        // Create disclosure and serialize to JSON using AOT-compatible method
        var disclosure = new Disclosure(salt, claimValue);
        var json = disclosure.ToJson();

        // Convert to base64url
        return Base64UrlEncoder.Encode(json);
    }
}
