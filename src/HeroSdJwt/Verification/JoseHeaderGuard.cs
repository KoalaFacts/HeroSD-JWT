using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Rejects malformed standard JOSE header values and unsupported extensions.
/// A valid signature does not make an unknown critical extension safe to ignore.
/// </summary>
internal static class JoseHeaderGuard
{
    internal static bool HasInvalidOrUnsupportedParameters(JsonElement header)
    {
        try
        {
            // RFC 7515 requires processing every critical extension. RFC 7797's
            // b64 parameter changes payload interpretation; it is not supported
            // even when set to true or supplied without crit.
            return header.ValueKind != JsonValueKind.Object ||
                   header.TryGetProperty("crit", out _) ||
                   header.TryGetProperty("b64", out _) ||
                   // RFC 7515 requires registered alg, kid, typ and cty values to
                   // be strings when present. Never interpret a malformed header
                   // as a valid signed token or call a key resolver for it.
                   (header.TryGetProperty("alg", out var alg) && !IsValidString(alg)) ||
                   (header.TryGetProperty("kid", out var kid) && !IsValidString(kid)) ||
                   (header.TryGetProperty("typ", out var typ) && !IsValidString(typ)) ||
                   (header.TryGetProperty("cty", out var cty) && !IsValidString(cty)) ||
                   // Use the same unambiguous-name policy for JOSE headers and
                   // JWT claim sets, including escaped JSON member names.
                   JsonObjectMemberGuard.HasInvalidOrDuplicateNames(header);
        }
        catch (InvalidOperationException)
        {
            return true; // Fail closed on invalid escaped names or string values.
        }
    }

    private static bool IsValidString(JsonElement value)
    {
        // String shape is insufficient: JsonElement.GetString throws when a
        // signed JOSE string contains an unpaired escaped UTF-16 surrogate.
        // Validate even optional metadata that a caller does not consume.
        return value.ValueKind == JsonValueKind.String && value.GetString() is not null;
    }
}
