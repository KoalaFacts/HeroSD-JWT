namespace HeroSdJwt.Primitives;

/// <summary>
/// Validates key identifiers per RFC 7515 and security requirements.
/// </summary>
internal static class KeyIdValidator
{
    private const int MAX_KEY_ID_LENGTH = 256;

    /// <summary>
    /// Validates a key identifier meets RFC 7515 and application requirements.
    /// </summary>
    /// <param name="keyId">The key identifier to validate.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when keyId is empty, exceeds 256 characters, or contains non-printable characters.
    /// </exception>
    public static void Validate(string keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new ArgumentException("Key ID cannot be empty or whitespace", nameof(keyId));
        }

        if (keyId.Length > MAX_KEY_ID_LENGTH)
        {
            throw new ArgumentException(
                $"Key ID length ({keyId.Length}) exceeds maximum allowed ({MAX_KEY_ID_LENGTH})",
                nameof(keyId));
        }

        // Check for non-printable characters (ASCII 32-126 are printable)
        // This prevents injection attacks via control characters
        if (keyId.Any(c => c is < ' ' or > '~'))
        {
            throw new ArgumentException(
                "Key ID contains non-printable characters. Only printable ASCII characters (32-126) are allowed.",
                nameof(keyId));
        }
    }
}
