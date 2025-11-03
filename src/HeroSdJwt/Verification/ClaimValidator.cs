
using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Validates JWT claims including temporal claims (exp, nbf, iat).
/// </summary>
public class ClaimValidator : IClaimValidator
{
    /// <summary>
    /// Validates temporal claims in a JWT payload with optional clock skew tolerance.
    /// </summary>
    /// <param name="payload">The decoded JWT payload as JsonElement.</param>
    /// <param name="options">Verification options including clock skew.</param>
    /// <param name="currentTime">Optional current time for testing; uses UtcNow if null.</param>
    /// <returns>True if all temporal claims are valid; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when payload or options is null.</exception>
    public bool ValidateTemporalClaims(
        JsonElement payload,
        SdJwtVerificationOptions options,
        DateTimeOffset? currentTime = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var now = currentTime ?? DateTimeOffset.UtcNow;
        var clockSkew = options.ClockSkew;

        // Validate expiration time (exp) - REQUIRED for SD-JWT per spec
        if (payload.TryGetProperty("exp", out var expElement))
        {
            if (!TryGetUnixTimestamp(expElement, out var exp))
            {
                return false;
            }

            // Token is expired if current time > exp + clock skew
            if (now > exp.AddSeconds(clockSkew.TotalSeconds))
            {
                return false;
            }
        }

        // Validate not-before time (nbf) - OPTIONAL
        if (payload.TryGetProperty("nbf", out var nbfElement))
        {
            if (!TryGetUnixTimestamp(nbfElement, out var nbf))
            {
                return false;
            }

            // Token not yet valid if current time < nbf - clock skew
            if (now < nbf.AddSeconds(-clockSkew.TotalSeconds))
            {
                return false;
            }
        }

        // Validate issued-at time (iat) - OPTIONAL
        // Reject tokens with iat in the future (with clock skew tolerance)
        if (payload.TryGetProperty("iat", out var iatElement))
        {
            if (!TryGetUnixTimestamp(iatElement, out var iat))
            {
                return false;
            }

            // Reject if issued in the future (current time < iat - clock skew)
            // This prevents accepting tokens with suspicious future timestamps
            if (now < iat.AddSeconds(-clockSkew.TotalSeconds))
            {
                return false; // Token issued in the future
            }
        }

        return true;
    }

    /// <summary>
    /// Validates issuer claim if expected issuer is configured.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="expectedIssuer">The expected issuer value.</param>
    /// <returns>True if issuer matches or expectedIssuer is null; otherwise, false.</returns>
    public bool ValidateIssuer(JsonElement payload, string? expectedIssuer)
    {
        if (string.IsNullOrWhiteSpace(expectedIssuer))
        {
            return true; // Issuer validation not required
        }

        if (!payload.TryGetProperty("iss", out var issElement))
        {
            return false; // Expected issuer but claim missing
        }

        var actualIssuer = issElement.GetString();
        return string.Equals(actualIssuer, expectedIssuer, StringComparison.Ordinal);
    }

    /// <summary>
    /// Validates audience claim if expected audience is configured.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="expectedAudience">The expected audience value.</param>
    /// <returns>True if audience matches or expectedAudience is null; otherwise, false.</returns>
    public bool ValidateAudience(JsonElement payload, string? expectedAudience)
    {
        if (string.IsNullOrWhiteSpace(expectedAudience))
        {
            return true; // Audience validation not required
        }

        if (!payload.TryGetProperty("aud", out var audElement))
        {
            return false; // Expected audience but claim missing
        }

        // Audience can be a string or array of strings
        if (audElement.ValueKind == JsonValueKind.String)
        {
            var actualAudience = audElement.GetString();
            return string.Equals(actualAudience, expectedAudience, StringComparison.Ordinal);
        }
        else if (audElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var aud in audElement.EnumerateArray())
            {
                if (aud.ValueKind == JsonValueKind.String &&
                    string.Equals(aud.GetString(), expectedAudience, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        return false;
    }

    /// <summary>
    /// Tries to parse a Unix timestamp from a JsonElement.
    /// </summary>
    /// <param name="element">The JSON element containing the timestamp.</param>
    /// <param name="timestamp">The parsed timestamp as DateTimeOffset.</param>
    /// <returns>True if parsing succeeded; otherwise, false.</returns>
    private static bool TryGetUnixTimestamp(JsonElement element, out DateTimeOffset timestamp)
    {
        timestamp = DateTimeOffset.MinValue;

        if (element.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        if (!element.TryGetInt64(out var unixSeconds))
        {
            return false;
        }

        try
        {
            timestamp = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
