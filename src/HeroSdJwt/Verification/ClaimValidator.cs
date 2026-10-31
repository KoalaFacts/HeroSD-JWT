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

        if (payload.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        // Direct consumers of IClaimValidator may not have constructed a verifier,
        // so enforce the same 0–5 minute skew policy here as at the verifier boundary.
        // An excessive skew could otherwise accept a token long after expiration.
        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > TimeSpan.FromMinutes(5))
        {
            return false;
        }

        var nowTicks = NumericDateParser.GetCurrentUnixTicks(currentTime ?? DateTimeOffset.UtcNow);
        var clockSkewTicks = options.ClockSkew.Ticks;

        // Validate expiration time (exp) - REQUIRED for SD-JWT per spec
        if (!payload.TryGetProperty("exp", out var expElement))
        {
            return false; // Missing required exp claim
        }

        if (!NumericDateParser.TryParseUnixTicks(expElement, out var expTicks))
        {
            return false;
        }

        // RFC 7519 Section 4.1.4 requires now to be strictly before exp.
        // Clock skew extends the deadline, not its inclusivity.
        if (nowTicks - expTicks >= clockSkewTicks)
        {
            return false;
        }

        // Validate not-before time (nbf) - OPTIONAL
        if (payload.TryGetProperty("nbf", out var nbfElement))
        {
            if (!NumericDateParser.TryParseUnixTicks(nbfElement, out var nbfTicks))
            {
                return false;
            }

            // Token not yet valid if current time < nbf - clock skew
            if (nbfTicks - nowTicks > clockSkewTicks)
            {
                return false;
            }
        }

        // Validate issued-at time (iat) - OPTIONAL
        // Reject tokens with iat in the future (with clock skew tolerance)
        if (payload.TryGetProperty("iat", out var iatElement))
        {
            if (!NumericDateParser.TryParseUnixTicks(iatElement, out var iatTicks))
            {
                return false;
            }

            // Reject if issued in the future (current time < iat - clock skew)
            // This prevents accepting tokens with suspicious future timestamps
            if (iatTicks - nowTicks > clockSkewTicks)
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
    /// <returns>True if the present issuer is a string and matches the configured issuer, or no matching policy is configured; otherwise, false.</returns>
    public bool ValidateIssuer(JsonElement payload, string? expectedIssuer)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var requiresIssuer = !string.IsNullOrWhiteSpace(expectedIssuer);
        if (!payload.TryGetProperty("iss", out var issElement))
        {
            return !requiresIssuer;
        }

        // RFC 7519 requires a StringOrURI issuer when the claim is present,
        // regardless of whether the caller configured an issuer policy.
        if (issElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        return !requiresIssuer ||
               string.Equals(issElement.GetString(), expectedIssuer, StringComparison.Ordinal);
    }

    /// <summary>
    /// Validates audience claim if expected audience is configured.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="expectedAudience">The expected audience value.</param>
    /// <returns>True if any present audience is well-formed and matches the configured audience, or no matching policy is configured; otherwise, false.</returns>
    public bool ValidateAudience(JsonElement payload, string? expectedAudience)
    {
        var audiences = string.IsNullOrWhiteSpace(expectedAudience)
            ? Array.Empty<string>()
            : [expectedAudience];

        return ValidateAudience(payload, audiences);
    }

    /// <summary>
    /// Validates audience claim if expected audience is configured.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="expectedAudiences">The expected audience values.</param>
    /// <returns>True if any present audience is well-formed and matches a configured audience, or no matching policy is configured; otherwise, false.</returns>
    public bool ValidateAudience(JsonElement payload, IReadOnlyCollection<string>? expectedAudiences)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        // The common no-audience-policy path should not allocate a set.
        // Create one only when at least one non-empty expected audience exists.
        HashSet<string>? expectedSet = null;
        if (expectedAudiences != null)
        {
            foreach (var expectedAudience in expectedAudiences)
            {
                if (!string.IsNullOrWhiteSpace(expectedAudience))
                {
                    expectedSet ??= new HashSet<string>(StringComparer.Ordinal);
                    _ = expectedSet.Add(expectedAudience);
                }
            }
        }

        if (!payload.TryGetProperty("aud", out var audElement))
        {
            return expectedSet is null;
        }

        // RFC 7519 requires an audience string or an array containing only
        // strings whenever the claim is present. Skipping audience matching
        // must not skip validating the signed claim's representation.
        if (audElement.ValueKind == JsonValueKind.String)
        {
            var actualAudience = audElement.GetString();
            return expectedSet is null ||
                   (actualAudience != null && expectedSet.Contains(actualAudience));
        }

        if (audElement.ValueKind == JsonValueKind.Array)
        {
            // Check every entry even after a match, so a malicious non-string
            // member cannot be hidden elsewhere in the array.
            var matched = false;
            foreach (var aud in audElement.EnumerateArray())
            {
                if (aud.ValueKind != JsonValueKind.String)
                {
                    return false;
                }

                if (aud.GetString() is string value && expectedSet?.Contains(value) == true)
                {
                    matched = true;
                }
            }

            return expectedSet is null || matched;
        }

        return false;
    }

}
