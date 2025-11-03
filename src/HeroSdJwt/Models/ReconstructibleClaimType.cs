namespace HeroSdJwt.Models;

/// <summary>
/// Specifies the type of reconstruction available for a claim.
/// </summary>
public enum ReconstructibleClaimType
{
    /// <summary>
    /// Claim can be reconstructed as a JSON array from disclosed array elements.
    /// </summary>
    Array = 0,

    /// <summary>
    /// Claim can be reconstructed as a JSON object from disclosed nested properties.
    /// </summary>
    Object = 1
}
