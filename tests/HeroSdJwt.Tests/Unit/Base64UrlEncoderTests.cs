using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;

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
        var bytes = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

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
        _ = Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.Encode((byte[])null!));
    }

    [Fact]
    public void Encode_WithNullString_ThrowsArgumentNullException()
    {
        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.Encode((string)null!));
    }

    [Fact]
    public void Encode_WithVeryLargeInput_ThrowsArgumentOutOfRangeException()
    {
        // Arrange - Create array larger than 10MB limit
        var largeBytes = new byte[11 * 1024 * 1024]; // 11MB

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => Base64UrlEncoder.Encode(largeBytes));
        Assert.Contains("must be less than or equal to", exception.Message);
    }

    [Fact]
    public void DecodeBytes_WithValidBase64Url_ReturnsOriginalBytes()
    {
        // Arrange
        var originalBytes = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
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
        _ = Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.DecodeBytes(null!));
    }

    [Fact]
    public void DecodeString_WithNullInput_ThrowsArgumentNullException()
    {
        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => Base64UrlEncoder.DecodeString(null!));
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
    public void DecodeBytes_WithVeryLargeInput_ThrowsArgumentOutOfRangeException()
    {
        // Arrange - Create string larger than 10MB limit
        var largeString = new string('A', 11 * 1024 * 1024); // 11MB

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => Base64UrlEncoder.DecodeBytes(largeString));
        Assert.Contains("must be less than or equal to", exception.Message);
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
        _ = Assert.Throws<SdJwtException>(() => Base64UrlEncoder.DecodeBytes(withPlus));
    }

    [Fact]
    public void EncodeAndDecode_AcceptLargeValuesBelowTheDocumentedTenMiBLimit()
    {
        // Eight MiB of binary data is accepted by Encode, but its base64url
        // representation exceeds ten MiB. Decode must not reject our own output.
        var bytes = new byte[8 * 1024 * 1024];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(i * 37);
        }

        var encoded = Base64UrlEncoder.Encode(bytes);
        var decoded = Base64UrlEncoder.DecodeBytes(encoded);

        Assert.Equal(bytes, decoded);
    }

    [Fact]
    public void DecodeBytes_LargePayload_DoesNotAllocateRedundantInputAndCopyBuffers()
    {
        // The hot-path decoder should only need its binary result, not an
        // additional UTF-8 copy of the base64url string and a copied output.
        // Warm up before measuring thread-local allocations to exclude JIT work.
        var source = new byte[16 * 1024];
        for (int i = 0; i < source.Length; i++)
        {
            source[i] = (byte)i;
        }

        var encoded = Base64UrlEncoder.Encode(source);
        _ = Base64UrlEncoder.DecodeBytes(encoded);
        _ = Base64UrlEncoder.DecodeBytes(encoded);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var decoded = Base64UrlEncoder.DecodeBytes(encoded);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(source, decoded);
        Assert.True(
            allocated < (source.Length * 2L) + 1024,
            $"Decoding {source.Length} bytes allocated {allocated} bytes, indicating redundant buffers.");
    }

    [Fact]
    public void Encode_WithOversizedAsciiString_DoesNotAllocateUtf8Buffer()
    {
        // A rejected untrusted input must not allocate an 11-MiB UTF-8
        // buffer merely to discover that it exceeds the 10-MiB limit.
        var text = new string('A', 11 * 1024 * 1024);

        var before = GC.GetAllocatedBytesForCurrentThread();
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Base64UrlEncoder.Encode(text));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(allocated < 64 * 1024,
            $"Rejecting an oversized ASCII input allocated {allocated} bytes.");
    }

    [Fact]
    public void Encode_WithOversizedUtf8String_DoesNotAllocateUtf8Buffer()
    {
        // A shorter UTF-16 string can still expand past the byte limit.
        // The encoder must count UTF-8 bytes before allocating that buffer.
        var text = new string('\u6F22', 4 * 1024 * 1024);

        var before = GC.GetAllocatedBytesForCurrentThread();
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => Base64UrlEncoder.Encode(text));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(allocated < 64 * 1024,
            $"Rejecting an oversized UTF-8 input allocated {allocated} bytes.");
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
