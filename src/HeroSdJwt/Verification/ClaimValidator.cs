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

        if (payload.ValueKind != JsonValueKind.Object ||
            JsonObjectMemberGuard.HasInvalidOrDuplicateNames(payload))
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
        if (payload.ValueKind != JsonValueKind.Object ||
            JsonObjectMemberGuard.HasInvalidOrDuplicateNames(payload))
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
        if (payload.ValueKind != JsonValueKind.Object ||
            JsonObjectMemberGuard.HasInvalidOrDuplicateNames(payload))
        {
            return false;
        }

        // Reject missing or malformed signed audiences before allocating a
        // lookup set for an application with many configured audiences.
        if (!payload.TryGetProperty("aud", out var audElement))
        {
            // A whitespace-only policy is intentionally unconstrained.
            if (expectedAudiences is not null)
            {
                foreach (var expectedAudience in expectedAudiences)
                {
                    if (!string.IsNullOrWhiteSpace(expectedAudience))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        if (audElement.ValueKind == JsonValueKind.Array)
        {
            // The entire array must be well-formed, even if an earlier entry
            // matches. Check before allocating the expected audience set.
            foreach (var audience in audElement.EnumerateArray())
            {
                if (audience.ValueKind != JsonValueKind.String)
                {
                    return false;
                }
            }
        }
        else if (audElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        // A signed JWT commonly contains a single audience. Scan the
        // configured allowlist directly rather than allocating a HashSet of
        // thousands of configured audiences for each verification.
        if (audElement.ValueKind == JsonValueKind.String)
        {
            if (!TryGetAudienceString(audElement, out var actualAudience))
            {
                return false;
            }
            var hasExpectedAudience = false;
            if (expectedAudiences is not null)
            {
                foreach (var expectedAudience in expectedAudiences)
                {
                    if (string.IsNullOrWhiteSpace(expectedAudience))
                    {
                        continue;
                    }

                    hasExpectedAudience = true;
                    if (string.Equals(actualAudience, expectedAudience, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }

            return !hasExpectedAudience;
        }

        if (expectedAudiences is null || expectedAudiences.Count == 0)
        {
            // A missing audience policy must not make malformed signed
            // StringOrURI entries acceptable. Decode every array member.
            foreach (var audience in audElement.EnumerateArray())
            {
                if (!TryGetAudienceString(audience, out _))
                {
                    return false;
                }
            }

            return true;
        }

        // With a single configured audience, scan the already shape-checked
        // signed array directly. The common one-audience policy should not
        // allocate a HashSet (or its buckets) on every verification.
        if (expectedAudiences.Count == 1)
        {
            foreach (var expectedAudience in expectedAudiences)
            {
                if (string.IsNullOrWhiteSpace(expectedAudience))
                {
                    return true;
                }

                var matched = false;
                foreach (var audience in audElement.EnumerateArray())
                {
                    if (!TryGetAudienceString(audience, out var actualAudience))
                    {
                        return false;
                    }

                    // Do not short-circuit after a match: a later audience
                    // can contain invalid escaped Unicode.
                    if (string.Equals(actualAudience, expectedAudience, StringComparison.Ordinal))
                    {
                        matched = true;
                    }
                }

                return matched;
            }

            return true;
        }

        // For a few configured audiences and signed array entries, bounded
        // comparisons avoid a per-verification HashSet. Decode every signed
        // entry before returning a match: a later JSON string with malformed
        // escaped Unicode must not be bypassed by an earlier matching entry.
        if (expectedAudiences.Count <= 4 && audElement.GetArrayLength() <= 4)
        {
            var hasExpectedAudience = false;
            foreach (var expectedAudience in expectedAudiences)
            {
                if (!string.IsNullOrWhiteSpace(expectedAudience))
                {
                    hasExpectedAudience = true;
                }
            }

            var smallArrayMatched = false;
            foreach (var audience in audElement.EnumerateArray())
            {
                if (!TryGetAudienceString(audience, out var actualAudience))
                {
                    return false;
                }

                foreach (var expectedAudience in expectedAudiences)
                {
                    if (!string.IsNullOrWhiteSpace(expectedAudience) &&
                        string.Equals(actualAudience, expectedAudience, StringComparison.Ordinal))
                    {
                        smallArrayMatched = true;
                    }
                }
            }

            return !hasExpectedAudience || smallArrayMatched;
        }

        // For larger policy/array combinations, retain the lookup strategy
        // so comparison costs do not scale as the product of both sizes.
        if (audElement.GetArrayLength() <= 8)
        {
            var actualAudiences = new HashSet<string>(StringComparer.Ordinal);
            foreach (var audience in audElement.EnumerateArray())
            {
                if (!TryGetAudienceString(audience, out var actualAudience))
                {
                    return false;
                }

                _ = actualAudiences.Add(actualAudience!);
            }

            var hasExpectedAudience = false;
            foreach (var expectedAudience in expectedAudiences)
            {
                if (string.IsNullOrWhiteSpace(expectedAudience))
                {
                    continue;
                }

                hasExpectedAudience = true;
                if (actualAudiences.Contains(expectedAudience))
                {
                    return true;
                }
            }

            return !hasExpectedAudience;
        }

        HashSet<string>? expectedSet = null;
        foreach (var expectedAudience in expectedAudiences)
        {
            if (!string.IsNullOrWhiteSpace(expectedAudience))
            {
                expectedSet ??= new HashSet<string>(StringComparer.Ordinal);
                _ = expectedSet.Add(expectedAudience);
            }
        }

        var matched = false;
        foreach (var audience in audElement.EnumerateArray())
        {
            if (!TryGetAudienceString(audience, out var actualAudience))
            {
                return false;
            }

            if (expectedSet?.Contains(actualAudience!) == true)
            {
                matched = true;
            }
        }

        return expectedSet is null || matched;
    }

    private static bool TryGetAudienceString(JsonElement audience, out string? value)
    {
        try
        {
            value = audience.GetString();
            return value is not null;
        }
        catch (InvalidOperationException)
        {
            // System.Text.Json can throw for invalid escaped surrogates.
            // This public boolean validator must fail closed, not accept a
            // partial audience array or leak a decoding exception.
            value = null;
            return false;
        }
    }
}
