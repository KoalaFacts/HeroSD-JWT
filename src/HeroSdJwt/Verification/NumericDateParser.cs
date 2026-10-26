using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Parses RFC 7519 NumericDate values into decimal 100-ns units.
/// Retaining fractional ticks keeps security boundaries exact even when a
/// JSON number is more precise than DateTimeOffset can represent.
/// </summary>
internal static class NumericDateParser
{
    private const decimal MIN_UNIX_SECONDS = -62_135_596_800M;
    private const decimal MAX_UNIX_SECONDS_EXCLUSIVE = 253_402_300_800M;

    internal static bool TryParseUnixTicks(JsonElement element, out decimal unixTicks)
    {
        unixTicks = default;

        if (element.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        // Preserve the cheap integer path for the overwhelmingly common form.
        if (element.TryGetInt64(out var wholeSeconds))
        {
            if (wholeSeconds < MIN_UNIX_SECONDS || wholeSeconds >= MAX_UNIX_SECONDS_EXCLUSIVE)
            {
                return false;
            }

            unixTicks = wholeSeconds * TimeSpan.TicksPerSecond;
            return true;
        }

        // Do not round to DateTimeOffset ticks: rounding can accept a token
        // issued a fraction of a tick in the future or older than max age.
        if (!element.TryGetDecimal(out var seconds) ||
            seconds < MIN_UNIX_SECONDS ||
            seconds >= MAX_UNIX_SECONDS_EXCLUSIVE)
        {
            return false;
        }

        unixTicks = seconds * TimeSpan.TicksPerSecond;
        return true;
    }

    internal static long GetCurrentUnixTicks(DateTimeOffset now) =>
        now.UtcTicks - DateTimeOffset.UnixEpoch.Ticks;
}
