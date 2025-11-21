using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using System.Linq;

namespace HeroSdJwt.Verification;

/// <summary>
/// Centralized validation for JWT key identifiers (kid) on the verifier side.
/// </summary>
internal static class KeyIdGuard
{
    private const int MAX_KEY_ID_LENGTH = 256;

    /// <summary>
    /// Validates a kid value and throws <see cref="SdJwtException"/> with a specific error code when invalid.
    /// </summary>
    public static void EnsureValid(string? keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new SdJwtException("JWT header contains empty 'kid' claim", ErrorCode.KeyIdEmpty);
        }

        if (keyId.Length > MAX_KEY_ID_LENGTH)
        {
            throw new SdJwtException(
                $"JWT 'kid' length ({keyId.Length}) exceeds maximum allowed length of {MAX_KEY_ID_LENGTH} characters",
                ErrorCode.KeyIdTooLong);
        }

        // Only printable ASCII (32-126) is allowed to prevent control-character injection in logs/metrics.
        if (keyId.Any(c => c < 32 || c > 126))
        {
            throw new SdJwtException(
                "JWT 'kid' contains non-printable characters. Only ASCII 32-126 are allowed.",
                ErrorCode.KeyIdInvalidCharacters);
        }
    }
}
