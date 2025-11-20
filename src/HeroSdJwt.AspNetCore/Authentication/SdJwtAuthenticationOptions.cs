using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.Authentication;

namespace HeroSdJwt.AspNetCore.Authentication;

/// <summary>
/// Options for configuring SD-JWT authentication in ASP.NET Core.
/// </summary>
public class SdJwtAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the core verification options.
    /// </summary>
    public SdJwtVerificationOptions VerificationOptions { get; set; } = new SdJwtVerificationOptions
    {
        ClockSkew = TimeSpan.FromMinutes(5),
        RequireKeyBinding = false,
        ExpectedKeyType = VerificationKeyType.Asymmetric
    };

    /// <summary>
    /// Gets or sets the key resolver function.
    /// This function is called to resolve the verification key based on the key ID (kid) from the JWT header.
    /// Required if JWTs contain a 'kid' header parameter.
    /// </summary>
    /// <remarks>
    /// The resolver should return the appropriate verification key (public key or shared secret) for the given key ID.
    /// Return null if the key ID is not recognized.
    /// </remarks>
    public KeyResolver? KeyResolver { get; set; }

    /// <summary>
    /// Gets or sets the fallback verification key.
    /// Used when the JWT does not contain a 'kid' header parameter.
    /// This supports backward compatibility with systems that don't implement key rotation.
    /// </summary>
    public byte[]? FallbackKey { get; set; }

    /// <summary>
    /// Gets or sets the name of the authorization header scheme.
    /// Default is "Bearer".
    /// The authentication handler will look for tokens in the format: "Bearer {token}".
    /// </summary>
    public string TokenScheme { get; set; } = SdJwtAuthenticationDefaults.BEARER_SCHEME;

    /// <summary>
    /// Gets or sets whether to save the verified SD-JWT token in the AuthenticationProperties.
    /// Default is false.
    /// When true, the original presentation string can be accessed via context.Properties.
    /// </summary>
    public bool SaveToken { get; set; } = false;

    /// <summary>
    /// Gets or sets the claim type to use for the user's name.
    /// Default is "name" (standard JWT claim).
    /// This claim will be used to populate HttpContext.User.Identity.Name.
    /// </summary>
    public string NameClaimType { get; set; } = "name";

    /// <summary>
    /// Gets or sets the claim type to use for the user's role.
    /// Default is "role" (standard JWT claim).
    /// This claim will be used for role-based authorization.
    /// </summary>
    public string RoleClaimType { get; set; } = "role";

    /// <summary>
    /// Validates the configuration and throws if invalid.
    /// Called by ASP.NET Core during authentication handler initialization.
    /// </summary>
    public override void Validate()
    {
        base.Validate();

        // Validate core verification options
        VerificationOptions?.Validate();

        if (VerificationOptions?.RequireKeyBinding == true &&
            string.IsNullOrWhiteSpace(VerificationOptions.ExpectedAudience))
        {
            throw new InvalidOperationException(
                "ExpectedAudience must be configured when key binding is required to prevent token replay across audiences.");
        }

        // Validate key configuration
        if (KeyResolver == null && FallbackKey == null)
        {
            throw new InvalidOperationException(
                "Either KeyResolver or FallbackKey must be configured. " +
                "Provide a KeyResolver for key rotation support, or FallbackKey for simple scenarios.");
        }
    }
}
