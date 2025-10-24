using System.Buffers.Text;
using HeroSdJwt.Exceptions;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;

namespace HeroSdJwt.Encoding;

/// <summary>
/// Provides Base64url encoding and decoding utilities using the BCL Base64Url class.
/// Base64url is defined in RFC 4648 Section 5.
/// This wrapper adds security features like DoS protection and domain-specific exceptions.
/// </summary>
internal static class Base64UrlEncoder
{
    /// <summary>
    /// Maximum input length to prevent DoS attacks through memory exhaustion.
    /// 10MB limit is reasonable for SD-JWT use cases.
    /// </summary>
    private const int maxInputLength = 10 * 1024 * 1024; // 10MB

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

        if (bytes.Length > maxInputLength)
        {
            throw new ArgumentException(
                $"Input exceeds maximum length of {maxInputLength} bytes",
                nameof(bytes));
        }

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

        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        return Encode(bytes);
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
    public static byte[] DecodeBytes(string base64Url)
    {
        ArgumentNullException.ThrowIfNull(base64Url);

        if (base64Url.Length > maxInputLength)
        {
            throw new ArgumentException(
                $"Input exceeds maximum length of {maxInputLength} characters",
                nameof(base64Url));
        }

        try
        {
            // Convert string to UTF-8 bytes for Base64Url.DecodeFromUtf8
            var utf8Bytes = System.Text.Encoding.UTF8.GetBytes(base64Url);

            // Calculate maximum possible decoded size
            var maxDecodedLength = Base64Url.GetMaxDecodedLength(utf8Bytes.Length);
            var buffer = new byte[maxDecodedLength];

            // Decode from UTF-8 base64url to bytes
            var status = Base64Url.DecodeFromUtf8(utf8Bytes, buffer, out _, out var bytesWritten);

            if (status != System.Buffers.OperationStatus.Done)
            {
                throw new FormatException("Invalid base64url encoding");
            }

            // Return only the written portion
            return buffer[..bytesWritten];
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

        var bytes = DecodeBytes(base64Url);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
