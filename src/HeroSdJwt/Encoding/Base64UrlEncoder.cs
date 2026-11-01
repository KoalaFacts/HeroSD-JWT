using HeroSdJwt.Exceptions;
using System.Buffers.Text;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;

namespace HeroSdJwt.Encoding;

/// <summary>
/// Provides Base64url encoding and decoding utilities using the BCL Base64Url class.
/// Base64url is defined in RFC 4648 Section 5.
/// This wrapper adds security features like DoS protection and domain-specific exceptions.
/// </summary>
public static class Base64UrlEncoder
{
    /// <summary>
    /// Maximum input length to prevent DoS attacks through memory exhaustion.
    /// 10MB limit is reasonable for SD-JWT use cases.
    /// </summary>
    private const int MAX_INPUT_LENGTH = 10 * 1024 * 1024; // 10MB

    // Base64url expands binary input by up to 4/3. The decode limit is
    // measured in resulting bytes, not encoded characters.
    private const int MAX_ENCODED_INPUT_LENGTH = ((MAX_INPUT_LENGTH + 2) / 3) * 4;

    // Reject non-UTF-8 JSON rather than silently replacing invalid bytes with U+FFFD.
    private static readonly System.Text.UTF8Encoding _strictUtf8 = new(false, true);

    /// <summary>
    /// Converts a byte array to a base64url-encoded string.
    /// Base64url encoding uses URL-safe characters: no +, /, or = padding.
    /// Uses System.Buffers.Text.Base64Url from .NET BCL.
    /// </summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <returns>Base64url-encoded string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when bytes is null.</exception>
    /// <exception cref="ArgumentException">Thrown when input exceeds maximum length.</exception>
    public static string Encode(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        ArgumentOutOfRangeException.ThrowIfGreaterThan(bytes.Length, MAX_INPUT_LENGTH, nameof(bytes));

        return Base64Url.EncodeToString(bytes);
    }

    /// <summary>
    /// Converts a UTF-8 string to a base64url-encoded string.
    /// </summary>
    /// <param name="text">The text to encode.</param>
    /// <returns>Base64url-encoded string.</returns>
    public static string Encode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        // Do not allocate a large UTF-8 buffer only to reject its size.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(text.Length, MAX_INPUT_LENGTH, nameof(text));

        // Each UTF-16 code unit can produce at most three UTF-8 bytes.
        // Common small inputs need no extra scan; large inputs must be
        // checked for multi-byte expansion before allocating the buffer.
        try
        {
            // Header, payload and Disclosure JSON is usually short. Encode
            // directly from strict UTF-16 into bounded stack storage, avoiding
            // a temporary UTF-8 byte[] on every signing operation.
            const int StackTextLimit = 256;
            if (text.Length <= StackTextLimit)
            {
                // Each UTF-16 code unit requires at most three UTF-8 bytes.
                // A surrogate pair occupies two units but encodes to four bytes.
                Span<byte> utf8Bytes = stackalloc byte[text.Length * 3];
                var bytesWritten = _strictUtf8.GetBytes(text.AsSpan(), utf8Bytes);
                return Base64Url.EncodeToString(utf8Bytes[..bytesWritten]);
            }

            if (text.Length > MAX_INPUT_LENGTH / 3)
            {
                var byteCount = _strictUtf8.GetByteCount(text);
                ArgumentOutOfRangeException.ThrowIfGreaterThan(byteCount, MAX_INPUT_LENGTH, nameof(text));
            }

            byte[] bytes = _strictUtf8.GetBytes(text);
            return Encode(bytes);
        }
        catch (System.Text.EncoderFallbackException ex)
        {
            throw new SdJwtException(
                "Invalid UTF-16 text in base64url input",
                ErrorCode.InvalidInput,
                ex);
        }
    }

    /// <summary>
    /// Decodes a base64url-encoded string to a byte array.
    /// Uses System.Buffers.Text.Base64Url from .NET BCL.
    /// </summary>
    /// <param name="base64Url">The base64url-encoded string.</param>
    /// <returns>Decoded byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when base64Url is null.</exception>
    /// <exception cref="ArgumentException">Thrown when input exceeds maximum length.</exception>
    /// <exception cref="SdJwtException">Thrown when input is not valid base64url.</exception>
    public static byte[] DecodeBytes(string base64Url) =>
        DecodeBytesCore(base64Url, requireJoseCanonical: true);

    // Digest equality intentionally compares decoded bytes, including padded
    // aliases, while externally supplied JOSE components must be canonical.
    internal static byte[] DecodeBytesForDigestComparison(string base64Url) =>
        DecodeBytesCore(base64Url, requireJoseCanonical: false);

    private static byte[] DecodeBytesCore(string base64Url, bool requireJoseCanonical)
    {
        ArgumentNullException.ThrowIfNull(base64Url);

        if (requireJoseCanonical)
        {
            // Encode accepts up to 10 MiB of bytes, which may require almost
            // 14 MiB of base64url characters. Bound the decoded size before
            // allowing the framework decoder to allocate its output buffer.
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                base64Url.Length, MAX_ENCODED_INPUT_LENGTH, nameof(base64Url));

            var completeGroups = base64Url.Length / 4;
            var remainder = base64Url.Length % 4;
            var decodedLength = completeGroups * 3 + (remainder == 2 ? 1 : remainder == 3 ? 2 : 0);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                decodedLength, MAX_INPUT_LENGTH, nameof(base64Url));
        }
        else
        {
            // Digest equality's permissive legacy aliases are not JOSE input.
            // Keep its existing bounded-string behavior unchanged.
            ArgumentOutOfRangeException.ThrowIfGreaterThan(base64Url.Length, MAX_INPUT_LENGTH, nameof(base64Url));
        }

        // RFC 7515 compact JWS components omit base64url padding and must
        // contain no whitespace. The general-purpose BCL decoder accepts both.
        if (requireJoseCanonical && base64Url.AsSpan().IndexOfAny("= \t\r\n") >= 0)
        {
            throw new SdJwtException("Invalid base64url encoding", ErrorCode.InvalidInput);
        }

        try
        {
            // Decode the existing UTF-16 input directly. Encoding it into a
            // temporary UTF-8 array and copying the output doubled allocation
            // pressure across every JWT and Disclosure decode.
            return Base64Url.DecodeFromChars(base64Url.AsSpan());
        }
        catch (FormatException ex)
        {
            throw new SdJwtException(
                "Invalid base64url encoding",
                ErrorCode.InvalidInput,
                ex);
        }
    }

    /// <summary>
    /// Decodes a base64url-encoded string to a UTF-8 string.
    /// </summary>
    /// <param name="base64Url">The base64url-encoded string.</param>
    /// <returns>Decoded UTF-8 string.</returns>
    public static string DecodeString(string base64Url)
    {
        ArgumentNullException.ThrowIfNull(base64Url);

        byte[] bytes = DecodeBytes(base64Url);
        try
        {
            return _strictUtf8.GetString(bytes);
        }
        catch (System.Text.DecoderFallbackException ex)
        {
            throw new SdJwtException(
                "Invalid UTF-8 text in base64url input",
                ErrorCode.InvalidInput,
                ex);
        }
    }
}
