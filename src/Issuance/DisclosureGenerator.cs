using HeroSdJwt.Common;
using HeroSdJwt.Core;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Generates disclosure documents with cryptographically secure salts.
/// </summary>
public class DisclosureGenerator
{
    /// <summary>
    /// Generates a base64url-encoded disclosure for the specified claim.
    /// Format: Base64url(JSON([salt, claim_name, claim_value]))
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

        // Create disclosure array: [salt, claim_name, claim_value]
        var disclosureArray = new object[] { salt, claimName, claimValue };

        // Serialize to JSON
        var json = JsonSerializer.Serialize(disclosureArray);

        // Convert to base64url
        return Base64UrlEncoder.Encode(json);
    }
}
