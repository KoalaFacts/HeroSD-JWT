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
               // RFC 7515 requires registered alg, kid, typ and cty values to
               // be strings when present. Never interpret a malformed header
               // as a valid signed token or call a key resolver for it.
               (header.TryGetProperty("alg", out var alg) && alg.ValueKind != JsonValueKind.String) ||
               (header.TryGetProperty("kid", out var kid) && kid.ValueKind != JsonValueKind.String) ||
               (header.TryGetProperty("typ", out var typ) && typ.ValueKind != JsonValueKind.String) ||
               (header.TryGetProperty("cty", out var cty) && cty.ValueKind != JsonValueKind.String);
    }
}
