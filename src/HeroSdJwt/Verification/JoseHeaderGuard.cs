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
        // RFC 7515 requires processing every critical extension. RFC 7797's
        // b64 parameter changes payload interpretation; it is not supported
        // even when set to true or supplied without crit.
        return header.ValueKind != JsonValueKind.Object ||
               header.TryGetProperty("crit", out _) ||
               header.TryGetProperty("b64", out _) ||
               // RFC 7515 Section 4.1.4 requires kid to be a string when present.
               // A malformed kid must never be mistaken for an absent one and
               // silently select the resolver's fallback key.
               (header.TryGetProperty("kid", out var kid) && kid.ValueKind != JsonValueKind.String);
    }
}
