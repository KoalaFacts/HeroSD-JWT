namespace HeroSdJwt.AspNetCore.Authentication;

/// <summary>
/// Default values used by SD-JWT authentication.
/// </summary>
public static class SdJwtAuthenticationDefaults
{
    /// <summary>
    /// The default authentication scheme for SD-JWT.
    /// </summary>
    public const string AUTHENTICATION_SCHEME = "SdJwt";

    /// <summary>
    /// The default display name for SD-JWT authentication.
    /// </summary>
    public const string DISPLAY_NAME = "SD-JWT";

    /// <summary>
    /// The default authorization header scheme.
    /// </summary>
    public const string BEARER_SCHEME = "Bearer";
}
