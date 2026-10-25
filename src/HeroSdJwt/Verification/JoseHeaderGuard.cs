using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Rejects JOSE protected-header semantics the library does not implement.
/// A valid signature does not make an unknown critical extension safe to ignore.
/// </summary>
internal static class JoseHeaderGuard
{
    internal static bool RequiresUnsupportedProcessing(JsonElement header)
    {
        // RFC 7515 requires processing every critical extension. RFC 7797's
        // b64 parameter changes payload interpretation; it is not supported
        // even when set to true or supplied without crit.
        return header.ValueKind != JsonValueKind.Object ||
               header.TryGetProperty("crit", out _) ||
               header.TryGetProperty("b64", out _);
    }
}
