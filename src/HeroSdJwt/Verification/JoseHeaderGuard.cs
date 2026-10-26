using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Rejects malformed standard JOSE header values and unsupported extensions.
/// A valid signature does not make an unknown critical extension safe to ignore.
/// </summary>
internal static class JoseHeaderGuard
{
    private const int MAX_SMALL_HEADER_PARAMETERS = 8;

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
                   (header.TryGetProperty("alg", out var alg) && alg.ValueKind != JsonValueKind.String) ||
                   (header.TryGetProperty("kid", out var kid) && kid.ValueKind != JsonValueKind.String) ||
                   (header.TryGetProperty("typ", out var typ) && typ.ValueKind != JsonValueKind.String) ||
                   (header.TryGetProperty("cty", out var cty) && cty.ValueKind != JsonValueKind.String) ||
                   // JsonElement.TryGetProperty picks the last duplicate. Reject
                   // ambiguity instead, including unknown extension names and
                   // names escaped with JSON unicode sequences.
                   HasDuplicateParameterNames(header);
        }
        catch (InvalidOperationException)
        {
            // JsonProperty.Name can throw while unescaping an invalid Unicode
            // surrogate. Fail closed instead of leaking an exception from
            // public boolean JWT verification APIs.
            return true;
        }
    }

    private static bool HasDuplicateParameterNames(JsonElement header)
    {
        var count = 0;
        foreach (var _ in header.EnumerateObject())
        {
            if (++count > MAX_SMALL_HEADER_PARAMETERS)
            {
                // Keep adversarial, many-property headers linear-time rather
                // than applying the small-header scan quadratically.
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in header.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        // Ordinary JOSE headers have only a handful of members. Comparing
        // pairs avoids allocating a HashSet on every token verification.
        var index = 0;
        foreach (var property in header.EnumerateObject())
        {
            var name = property.Name;
            var candidateIndex = 0;
            foreach (var candidate in header.EnumerateObject())
            {
                if (candidateIndex++ > index && candidate.NameEquals(name))
                {
                    return true;
                }
            }

            index++;
        }

        return false;
    }
}
