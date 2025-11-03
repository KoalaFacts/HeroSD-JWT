using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using System.Text;
using System.Text.Json;
using HeroSdJwt.Encoding;
using Xunit;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Contract tests for SdJwtBuilder.WithKeyId() method.
/// Validates that key IDs are properly included in JWT headers.
/// </summary>
public class SdJwtBuilderKeyIdTests
{
    private readonly KeyGenerator keyGen = KeyGenerator.Instance;

    [Fact]
    public void WithKeyId_ValidKeyId_IncludesKidInJwtHeader()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();
        var keyId = "key-2024-10";

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("email", "test@example.com")
            .MakeSelective("email")
            .WithKeyId(keyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        Assert.Equal(3, jwtParts.Length);

        var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(keyId, kidElement.GetString());
    }

    [Fact]
    public void WithKeyId_EmptyString_ThrowsArgumentException()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithKeyId("")
                .SignWithHmac(hmacKey)
                .Build());

        Assert.Contains("Key ID cannot be empty", exception.Message);
    }

    [Fact]
    public void WithKeyId_ExceedsMaxLength_ThrowsArgumentException()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();
        var longKeyId = new string('x', 257); // 257 characters (max is 256)

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithKeyId(longKeyId)
                .SignWithHmac(hmacKey)
                .Build());

        Assert.Contains("exceeds maximum allowed", exception.Message);
    }

    [Fact]
    public void WithKeyId_NonPrintableCharacters_ThrowsArgumentException()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();
        var invalidKeyId = "key\nwith\nnewlines"; // Contains newline (ASCII 10)

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithKeyId(invalidKeyId)
                .SignWithHmac(hmacKey)
                .Build());

        Assert.Contains("non-printable characters", exception.Message);
    }

    [Fact]
    public void WithKeyId_CaseSensitive_PreservesCase()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();
        var keyId = "Key-MiXeD-CaSe-2024";

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithKeyId(keyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(keyId, kidElement.GetString()); // Exact case preserved
    }

    [Fact]
    public void WithoutKeyId_DoesNotIncludeKidInJwtHeader()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("email", "test@example.com")
            .MakeSelective("email")
            .SignWithHmac(hmacKey)
            .Build();

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.False(header.TryGetProperty("kid", out _)); // kid should not be present
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("RS256")]
    [InlineData("ES256")]
    public void WithKeyId_MultipleAlgorithms_IncludesKidForAll(string algorithmName)
    {
        // Arrange
        var keyId = $"test-key-{algorithmName}";
        byte[] signingKey;
        Action<SdJwtBuilder> signMethod;

        switch (algorithmName)
        {
            case "HS256":
                signingKey = keyGen.GenerateHmacKey();
                signMethod = builder => builder.SignWithHmac(signingKey);
                break;
            case "RS256":
                (signingKey, _) = keyGen.GenerateRsaKeyPair();
                signMethod = builder => builder.SignWithRsa(signingKey);
                break;
            case "ES256":
                (signingKey, _) = keyGen.GenerateEcdsaKeyPair();
                signMethod = builder => builder.SignWithEcdsa(signingKey);
                break;
            default:
                throw new InvalidOperationException($"Unknown algorithm: {algorithmName}");
        }

        // Act
        var builder = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithKeyId(keyId);
        signMethod(builder);
        var sdJwt = builder.Build();

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(keyId, kidElement.GetString());
        Assert.True(header.TryGetProperty("alg", out var algElement));
        Assert.Equal(algorithmName, algElement.GetString());
    }

    [Fact]
    public void WithKeyId_WhitespaceOnly_ThrowsArgumentException()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithKeyId("   ")
                .SignWithHmac(hmacKey)
                .Build());

        Assert.Contains("Key ID cannot be empty", exception.Message);
    }

    [Fact]
    public void WithKeyId_Null_ThrowsArgumentNullException()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtBuilder.Create()
                .WithClaim("sub", "user-123")
                .WithKeyId(null!)
                .SignWithHmac(hmacKey)
                .Build());
    }

    [Fact]
    public void WithKeyId_MaxLength_IncludesKidInHeader()
    {
        // Arrange
        var hmacKey = keyGen.GenerateHmacKey();
        var keyId = new string('x', 256); // Exactly 256 characters (at the limit)

        // Act
        var sdJwt = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithKeyId(keyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Assert
        var jwtParts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(jwtParts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(keyId, kidElement.GetString());
    }
}
