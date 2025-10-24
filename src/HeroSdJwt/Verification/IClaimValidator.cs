using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Interface for validating JWT claims including temporal claims (exp, nbf, iat).
/// </summary>
public interface IClaimValidator
{
    /// <summary>
    /// Validates temporal claims in a JWT payload with optional clock skew tolerance.
    /// </summary>
    /// <param name="payload">The decoded JWT payload as JsonElement.</param>
    /// <param name="options">Verification options including clock skew.</param>
    /// <param name="currentTime">Optional current time for testing; uses UtcNow if null.</param>
    /// <returns>True if all temporal claims are valid; otherwise, false.</returns>
    bool ValidateTemporalClaims(
        JsonElement payload,
        SdJwtVerificationOptions options,
        DateTimeOffset? currentTime = null);

    /// <summary>
    /// Validates the issuer claim (iss) if configured.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="expectedIssuer">Expected issuer value (null to skip validation).</param>
    /// <returns>True if issuer is valid or not configured; otherwise, false.</returns>
    bool ValidateIssuer(JsonElement payload, string? expectedIssuer);

    /// <summary>
    /// Validates the audience claim (aud) if configured.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="expectedAudience">Expected audience value (null to skip validation).</param>
    /// <returns>True if audience is valid or not configured; otherwise, false.</returns>
    bool ValidateAudience(JsonElement payload, string? expectedAudience);
}
