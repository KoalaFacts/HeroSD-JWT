using System.Text.Json;

namespace HeroSdJwt.Verification;

/// <summary>
/// Parses RFC 7519 NumericDate values, including fractional Unix seconds,
/// without rounding an expiry or freshness boundary in the caller's favor.
/// </summary>
internal static class NumericDateParser
{
    private const decimal MIN_UNIX_SECONDS = -62_135_596_800M;
    private const decimal MAX_UNIX_SECONDS_EXCLUSIVE = 253_402_300_800M;

    internal static bool TryParse(JsonElement element, out DateTimeOffset timestamp)
    {
        timestamp = default;

        if (element.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        // Preserve the allocation-free, exact integer fast path.
        if (element.TryGetInt64(out var wholeSeconds))
        {
            try
            {
                timestamp = DateTimeOffset.FromUnixTimeSeconds(wholeSeconds);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }

        // NumericDate is a JSON number, not necessarily an integer. Decimal
        // avoids floating point imprecision at tight temporal boundaries.
        if (!element.TryGetDecimal(out var seconds) ||
            seconds < MIN_UNIX_SECONDS ||
            seconds >= MAX_UNIX_SECONDS_EXCLUSIVE)
        {
            return false;
        }

        // DateTimeOffset represents 100-ns ticks. Truncation rejects artificial
        // rounding up over an expiry or key-binding freshness boundary.
        var ticks = (long)decimal.Truncate(seconds * TimeSpan.TicksPerSecond);
        try
        {
            timestamp = DateTimeOffset.UnixEpoch.AddTicks(ticks);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }
}
