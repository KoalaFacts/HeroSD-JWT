using HeroSdJwt.Common;
using System.Text;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for Base64Url encoding and decoding utilities.
/// Validates RFC 4648 Section 5 compliance and security features.
/// </summary>
public class Base64UrlEncoderTests
{
    [Fact]
    public void Encode_WithBytes_ReturnsBase64UrlString()
    {
        // Arrange
        var bytes = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        var encoded = Base64UrlEncoder.Encode(bytes);

        // Assert
        Assert.NotNull(encoded);
        Assert.NotEmpty(encoded);
        // Base64url should not contain +, /, or = characters
        Assert.DoesNotContain("+", encoded);
        Assert.DoesNotContain("/", encoded);
        Assert.DoesNotContain("=", encoded);
    }

    [Fact]
    public void Encode_WithString_ReturnsBase64UrlString()
    {
        // Arrange
        var text = "Test string with unicode: \u00e9\u00f1";

        // Act
        var encoded = Base64UrlEncoder.Encode(text);

        // Assert
        Assert.NotNull(encoded);
        Assert.NotEmpty(encoded);
        Assert.DoesNotContain("+", encoded);
        Assert.DoesNotContain("/", encoded);
        Assert.DoesNotContain("=", encoded);
    }

    [Fact]
    public void Encode_WithEmptyBytes_ReturnsEmptyString()
    {
        // Arrange
        var bytes = Array.Empty<byte>();

        // Act
        var encoded = Base64UrlEncoder.Encode(bytes);

        // Assert
        Assert.Equal(string.Empty, encoded);
    }

    [Fact]
    public void Encode_WithNullBytes_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.Encode((byte[])null!));
    }

    [Fact]
    public void Encode_WithNullString_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.Encode((string)null!));
    }

    [Fact]
    public void Encode_WithVeryLargeInput_ThrowsArgumentException()
    {
        // Arrange - Create array larger than 10MB limit
        var largeBytes = new byte[11 * 1024 * 1024]; // 11MB

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => Base64UrlEncoder.Encode(largeBytes));
        Assert.Contains("maximum length", exception.Message);
    }

    [Fact]
    public void DecodeBytes_WithValidBase64Url_ReturnsOriginalBytes()
    {
        // Arrange
        var originalBytes = Encoding.UTF8.GetBytes("Hello, World!");
        var encoded = Base64UrlEncoder.Encode(originalBytes);

        // Act
        var decoded = Base64UrlEncoder.DecodeBytes(encoded);

        // Assert
        Assert.Equal(originalBytes, decoded);
    }

    [Fact]
    public void DecodeString_WithValidBase64Url_ReturnsOriginalString()
    {
        // Arrange
        var originalString = "Test with special chars: !@#$%^&*()";
        var encoded = Base64UrlEncoder.Encode(originalString);

        // Act
        var decoded = Base64UrlEncoder.DecodeString(encoded);

        // Assert
        Assert.Equal(originalString, decoded);
    }

    [Fact]
    public void DecodeBytes_WithNullInput_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.DecodeBytes(null!));
    }

    [Fact]
    public void DecodeString_WithNullInput_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.DecodeString(null!));
    }

    [Fact]
    public void DecodeBytes_WithInvalidBase64Url_ThrowsSdJwtException()
    {
        // Arrange
        var invalidBase64 = "not valid base64url!!!";

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(invalidBase64));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
        Assert.Contains("base64url", exception.Message);
    }

    [Fact]
    public void DecodeBytes_WithVeryLargeInput_ThrowsArgumentException()
    {
        // Arrange - Create string larger than 10MB limit
        var largeString = new string('A', 11 * 1024 * 1024); // 11MB

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => Base64UrlEncoder.DecodeBytes(largeString));
        Assert.Contains("maximum length", exception.Message);
    }

    [Fact]
    public void EncodeAndDecode_RoundTrip_PreservesData()
    {
        // Arrange
        var testCases = new[]
        {
            "Simple text",
            "UTF-8: \u4e2d\u6587",  // Chinese characters
            "Emojis: \ud83d\ude00\ud83d\ude01",  // Emoji
            string.Empty,
            "a",  // Single character
            new string('x', 1000)  // Long string
        };

        foreach (var testCase in testCases)
        {
            // Act
            var encoded = Base64UrlEncoder.Encode(testCase);
            var decoded = Base64UrlEncoder.DecodeString(encoded);

            // Assert
            Assert.Equal(testCase, decoded);
        }
    }

    [Fact]
    public void Encode_ProducesUrlSafeOutput()
    {
        // Arrange - Data that would produce +, /, = in standard Base64
        var bytes = new byte[] { 0xFB, 0xFF, 0xBF, 0x3E, 0x3F };

        // Act
        var encoded = Base64UrlEncoder.Encode(bytes);

        // Assert - Base64url uses - and _ instead of + and /
        Assert.DoesNotContain("+", encoded);
        Assert.DoesNotContain("/", encoded);
        Assert.DoesNotContain("=", encoded);  // No padding
        Assert.Matches("^[A-Za-z0-9_-]+$", encoded);  // Only URL-safe chars
    }

    [Fact]
    public void DecodeBytes_WithStandardBase64Characters_ThrowsException()
    {
        // Arrange - Standard Base64 with + and / (not Base64url)
        var standardBase64 = "SGVsbG8gV29ybGQh"; // Valid Base64url
        var withPlus = standardBase64.Replace("S", "+");  // Make it invalid

        // Act & Assert
        Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(withPlus));
    }

    [Fact]
    public void EncodeAndDecode_WithBinaryData_PreservesBytes()
    {
        // Arrange
        var binaryData = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            binaryData[i] = (byte)i;
        }

        // Act
        var encoded = Base64UrlEncoder.Encode(binaryData);
        var decoded = Base64UrlEncoder.DecodeBytes(encoded);

        // Assert
        Assert.Equal(binaryData, decoded);
    }
}
