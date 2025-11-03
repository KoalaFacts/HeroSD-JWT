using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Encoding;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Security-focused tests for JWT key ID validation.
/// Tests US3: Security aspects of key rotation - validates protection against
/// injection attacks, excessive length attacks, and malformed input.
///
/// These tests ensure the key ID validation logic properly rejects:
/// - Non-printable characters (potential injection vectors)
/// - Excessive lengths (DoS/buffer overflow prevention)
/// - Empty strings (invalid configuration)
/// </summary>
public class KeyIdSecurityTests
{
    private readonly KeyGenerator keyGen = new();

    [Theory]
    [InlineData("\n")]
    [InlineData("\r")]
    [InlineData("\t")]
    [InlineData("\0")]
    [InlineData("key\ninjection")]
    [InlineData("key\u0000inject")]
    [InlineData("\u0001secret")]
    [InlineData("key\u001Fattack")]
    [InlineData("normal\u007Fkey")]
    public void KeyId_InjectionAttempt_Rejected(string maliciousKeyId)
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act & Assert - Attempt to use key ID with non-printable characters
        var exception = Assert.Throws<ArgumentException>(() =>
        {
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                .WithKeyId(maliciousKeyId)
                .SignWithHmac(hmacKey)
                .Build();
        });

        // Whitespace chars will trigger "empty or whitespace", others will trigger "non-printable"
        var isAcceptable = exception.Message.Contains("empty", StringComparison.OrdinalIgnoreCase) ||
                          exception.Message.Contains("whitespace", StringComparison.OrdinalIgnoreCase) ||
                          exception.Message.Contains("non-printable", StringComparison.OrdinalIgnoreCase);
        Assert.True(isAcceptable, $"Expected validation error, got: {exception.Message}");
    }

    [Theory]
    [InlineData(257)]
    [InlineData(300)]
    [InlineData(500)]
    [InlineData(1000)]
    [InlineData(10000)]
    public void KeyId_ExcessiveLength_Rejected(int length)
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();
        var excessiveKeyId = new string('k', length);

        // Act & Assert - Attempt to use key ID exceeding 256 character limit
        var exception = Assert.Throws<ArgumentException>(() =>
        {
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                .WithKeyId(excessiveKeyId)
                .SignWithHmac(hmacKey)
                .Build();
        });

        Assert.Contains("256", exception.Message);
        Assert.Contains(length.ToString(), exception.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\t")]
    [InlineData(" \t\n ")]
    public void KeyId_EmptyString_Rejected(string emptyKeyId)
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act & Assert - Attempt to use empty/whitespace key ID
        var exception = Assert.Throws<ArgumentException>(() =>
        {
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                .WithKeyId(emptyKeyId)
                .SignWithHmac(hmacKey)
                .Build();
        });

        Assert.Contains("empty", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void KeyId_MaxLengthBoundary_Accepts256Characters()
    {
        // Arrange - Test exactly 256 characters (maximum allowed)
        var hmacKey = keyGen.GenerateHmacKey();
        var maxLengthKeyId = new string('k', 256);

        // Act - Should succeed with exactly 256 characters
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(maxLengthKeyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert - Verify key ID was accepted and present in JWT header
        Assert.NotNull(sdJwt);

        // Decode JWT header to verify kid
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(maxLengthKeyId, kidElement.GetString());
    }

    [Fact]
    public void KeyId_MinLengthBoundary_Accepts1Character()
    {
        // Arrange - Test minimum valid length (1 character)
        var hmacKey = keyGen.GenerateHmacKey();
        var minLengthKeyId = "k";

        // Act - Should succeed with single character
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(minLengthKeyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert - Verify key ID was accepted
        Assert.NotNull(sdJwt);

        // Decode JWT header to verify kid
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(minLengthKeyId, kidElement.GetString());
    }

    [Theory]
    [InlineData("key-2024")]
    [InlineData("KeyID_123")]
    [InlineData("key.id@domain")]
    [InlineData("KEY-ID-2024-10-25")]
    [InlineData("key:id:version")]
    [InlineData("key|pipe|separated")]
    [InlineData("!@#$%^&*()-_=+[]{}|;:',.<>?")]
    public void KeyId_PrintableAscii_Accepted(string validKeyId)
    {
        // Arrange - Test various valid printable ASCII characters
        var hmacKey = keyGen.GenerateHmacKey();

        // Act - Should succeed with all printable ASCII
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(validKeyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
    }

    [Fact]
    public void KeyId_Null_ThrowsArgumentNullException()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act & Assert - Null key ID should throw ArgumentNullException
        Assert.Throws<ArgumentNullException>(() =>
        {
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                .WithKeyId(null!)
                .SignWithHmac(hmacKey)
                .Build();
        });
    }

    [Theory]
    [InlineData("key<script>alert('xss')</script>")]
    [InlineData("key'; DROP TABLE keys;--")]
    [InlineData("key\"; rm -rf /;")]
    [InlineData("key${env:SECRET}")]
    public void KeyId_InjectionPatterns_SafelyHandled(string injectionAttempt)
    {
        // Arrange - Test common injection patterns are safely rejected or escaped
        var hmacKey = keyGen.GenerateHmacKey();

        // Act - These strings contain only printable ASCII, so they should be accepted
        // (injection protection relies on printable ASCII validation, not pattern matching)
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(injectionAttempt)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert - Verify it's stored as literal string in JWT header (not interpreted)
        Assert.NotNull(sdJwt);

        // Decode JWT header to verify kid is stored verbatim
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(injectionAttempt, kidElement.GetString()); // Stored verbatim, not interpreted
    }
}
