using HeroSdJwt.Primitives;
using Xunit;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for KeyIdValidator.Validate method.
/// </summary>
public class KeyIdValidationTests
{
    [Fact]
    public void Validate_ValidKeyId_DoesNotThrow()
    {
        // Arrange
        var validKeyId = "key-2024-10";

        // Act & Assert
        var exception = Record.Exception(() => KeyIdValidator.Validate(validKeyId));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(""));
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Validate_WhitespaceOnly_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate("   "));
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Validate_Null_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => KeyIdValidator.Validate(null!));
    }

    [Fact]
    public void Validate_ExceedsMaxLength_ThrowsArgumentException()
    {
        // Arrange
        var longKeyId = new string('x', 257); // 257 characters

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(longKeyId));
        Assert.Contains("exceeds maximum allowed", exception.Message);
        Assert.Contains("256", exception.Message);
    }

    [Fact]
    public void Validate_MaxLength_DoesNotThrow()
    {
        // Arrange
        var keyId = new string('x', 256); // Exactly 256 characters

        // Act & Assert
        var exception = Record.Exception(() => KeyIdValidator.Validate(keyId));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_ContainsNewline_ThrowsArgumentException()
    {
        // Arrange
        var keyIdWithNewline = "key\nid";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithNewline));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void Validate_ContainsTab_ThrowsArgumentException()
    {
        // Arrange
        var keyIdWithTab = "key\tid";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithTab));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void Validate_ContainsNullByte_ThrowsArgumentException()
    {
        // Arrange
        var keyIdWithNull = "key\0id";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithNull));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void Validate_ContainsBell_ThrowsArgumentException()
    {
        // Arrange
        var keyIdWithBell = "key\aid"; // ASCII 7 (bell)

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithBell));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Theory]
    [InlineData("simple-key")]
    [InlineData("key-2024-10-24")]
    [InlineData("prod_rsa_v2")]
    [InlineData("KEY-UPPERCASE")]
    [InlineData("key.with.dots")]
    [InlineData("key:with:colons")]
    [InlineData("key/with/slashes")]
    [InlineData("key@example.com")]
    [InlineData("key#123")]
    [InlineData("key$%^&*()")]
    [InlineData("0123456789")]
    [InlineData("~`!@#$%^&*()_+-={}[]|:;<>?,./")]
    public void Validate_PrintableAsciiCharacters_DoesNotThrow(string keyId)
    {
        // Act & Assert
        var exception = Record.Exception(() => KeyIdValidator.Validate(keyId));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_UnicodeCharacters_ThrowsArgumentException()
    {
        // Arrange - Unicode characters outside ASCII range
        var keyIdWithUnicode = "key-é-ñ";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithUnicode));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void Validate_EmojiCharacters_ThrowsArgumentException()
    {
        // Arrange
        var keyIdWithEmoji = "key-🔑";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithEmoji));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void Validate_Delete_ThrowsArgumentException()
    {
        // Arrange - ASCII 127 (DEL) is non-printable
        var keyIdWithDelete = "key\x7Fid";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => KeyIdValidator.Validate(keyIdWithDelete));
        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void Validate_SpaceCharacter_DoesNotThrow()
    {
        // Arrange - Space (ASCII 32) is printable
        var keyIdWithSpace = "key with spaces";

        // Act & Assert
        var exception = Record.Exception(() => KeyIdValidator.Validate(keyIdWithSpace));
        Assert.Null(exception);
    }

    [Fact]
    public void Validate_TildeCharacter_DoesNotThrow()
    {
        // Arrange - Tilde (ASCII 126) is printable
        var keyIdWithTilde = "key~id~2024";

        // Act & Assert
        var exception = Record.Exception(() => KeyIdValidator.Validate(keyIdWithTilde));
        Assert.Null(exception);
    }
}
