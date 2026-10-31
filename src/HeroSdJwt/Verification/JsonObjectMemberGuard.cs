using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Rejects duplicate JSON object member names without allocating for common
/// small objects. Invalid escaped Unicode names also fail closed.
/// </summary>
internal static class JsonObjectMemberGuard
{
    private const int MAX_SMALL_OBJECT_MEMBERS = 8;

    // Disclosure values may contain objects at any nesting level. Reuse the
    // same unambiguous-name check as the JWT verifier without allocating a
    // collection for primitive values or arrays without object members.
    internal static bool HasInvalidOrDuplicateNamesRecursively(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            if (HasInvalidOrDuplicateNames(value))
            {
                return true;
            }

            foreach (var property in value.EnumerateObject())
            {
                if (HasInvalidOrDuplicateNamesRecursively(property.Value))
                {
                    return true;
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in value.EnumerateArray())
            {
                if (HasInvalidOrDuplicateNamesRecursively(element))
                {
                    return true;
                }
            }
        }

        return false;
    }

    internal static bool HasInvalidOrDuplicateNames(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return true;
        }

        try
        {
            var count = 0;
            foreach (var _ in value.EnumerateObject())
            {
                if (++count > MAX_SMALL_OBJECT_MEMBERS)
                {
                    // Keep large untrusted objects linear-time.
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in value.EnumerateObject())
                    {
                        if (!seen.Add(property.Name))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }

            // Most JWTs have a small number of claims, so avoid a HashSet.
            var index = 0;
            foreach (var property in value.EnumerateObject())
            {
                var name = property.Name;
                var candidateIndex = 0;
                foreach (var candidate in value.EnumerateObject())
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
        catch (InvalidOperationException)
        {
            // JsonProperty.Name throws for malformed escaped Unicode surrogate
            // pairs. Never leak that exception from a public validation API.
            return true;
        }
    }
}
