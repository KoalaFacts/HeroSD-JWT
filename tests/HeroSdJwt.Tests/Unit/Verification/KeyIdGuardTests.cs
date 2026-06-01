using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Tests for <see cref="KeyIdGuard"/>, the verifier-side guard that rejects malformed or
/// abusive 'kid' values before they reach key resolution, logging, or metrics. This prevents
/// log-injection and resource-exhaustion via oversized/control-character key identifiers.
/// </summary>
public class KeyIdGuardTests
{
    [Theory]
    [InlineData("key-1")]
    [InlineData("https://issuer.example.com/keys/2024")]
    [InlineData("a")]
    public void EnsureValid_WithPrintableAsciiKeyId_DoesNotThrow(string keyId)
    {
        Assert.Null(Record.Exception(() => KeyIdGuard.EnsureValid(keyId)));
    }

    [Fact]
    public void EnsureValid_WithNullKeyId_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => KeyIdGuard.EnsureValid(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void EnsureValid_WithEmptyOrWhitespaceKeyId_ThrowsKeyIdEmpty(string keyId)
    {
        var ex = Assert.Throws<SdJwtException>(() => KeyIdGuard.EnsureValid(keyId));
        Assert.Equal(ErrorCode.KeyIdEmpty, ex.ErrorCode);
    }

    [Fact]
    public void EnsureValid_WithOverlongKeyId_ThrowsKeyIdTooLong()
    {
        var keyId = new string('a', 257);

        var ex = Assert.Throws<SdJwtException>(() => KeyIdGuard.EnsureValid(keyId));
        Assert.Equal(ErrorCode.KeyIdTooLong, ex.ErrorCode);
    }

    [Fact]
    public void EnsureValid_AtMaxLength_DoesNotThrow()
    {
        var keyId = new string('a', 256);

        Assert.Null(Record.Exception(() => KeyIdGuard.EnsureValid(keyId)));
    }

    public static TheoryData<string> NonPrintableKeyIds()
    {
        return
        [
            "key" + (char)0x0A + "newline", // LF control char (< 32)
            "key" + (char)0x00 + "nul",     // embedded NUL (< 32)
            "key" + (char)0x7F + "del",     // DEL (127, above printable range)
            "caf" + (char)0x00E9,           // non-ASCII 'é' (> 126)
        ];
    }

    [Theory]
    [MemberData(nameof(NonPrintableKeyIds))]
    public void EnsureValid_WithNonPrintableOrNonAscii_ThrowsInvalidCharacters(string keyId)
    {
        var ex = Assert.Throws<SdJwtException>(() => KeyIdGuard.EnsureValid(keyId));
        Assert.Equal(ErrorCode.KeyIdInvalidCharacters, ex.ErrorCode);
    }
}
