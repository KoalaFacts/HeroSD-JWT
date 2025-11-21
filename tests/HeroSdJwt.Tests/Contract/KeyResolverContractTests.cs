using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Encoding;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Contract tests for key resolver functionality in SD-JWT verification.
/// Validates that verifiers can resolve key IDs to verification keys.
/// </summary>
public class KeyResolverContractTests
{
    private readonly KeyGenerator _keyGen = KeyGenerator.Instance;

    [Fact]
    public void VerifyPresentation_WithKeyResolver_ResolvesKeyId()
    {
        // Arrange - Create SD-JWT with key ID
        var hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "key-v1";

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("email", "alice@example.com")
            .MakeSelective("email")
            .WithKeyId(keyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Create key resolver
        var keys = new Dictionary<string, byte[]>
        {
            [keyId] = hmacKey
        };
        KeyResolver resolver = kid => keys.GetValueOrDefault(kid);

        // Act
        var verifier = TestHelpers.CreateVerifier();
        var presentation = sdJwt.ToPresentation("email"); // Reveal the selective claim

        // First verify it works with direct key (baseline test)
        var directResult = verifier.TryVerifyPresentation(presentation, hmacKey);
        Assert.True(directResult.IsValid, $"Baseline verification failed: {string.Join(", ", directResult.Errors)}");

        // Now test with key resolver
        var result = verifier.TryVerifyPresentation(presentation, resolver);

        // Assert
        Assert.True(result.IsValid, $"Verification failed with errors: {string.Join(", ", result.Errors)}");
        Assert.Equal("alice@example.com", result.DisclosedClaims["email"].GetString());
    }

    [Fact]
    public void VerifyPresentation_UnknownKeyId_ThrowsException()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "unknown-key";

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(keyId)
            .SignWithHmac(hmacKey)
            .Build();

        // Resolver returns null for unknown keys
        KeyResolver resolver = kid => null;

        // Act & Assert
        var verifier = TestHelpers.CreateVerifier();
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(sdJwt.ToPresentation(), resolver));

        Assert.Equal(ErrorCode.KeyIdNotFound, exception.ErrorCode);
        Assert.Contains("could not find", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryVerifyPresentation_UnknownKeyId_ReturnsInvalidResult()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "unknown-key";

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(keyId)
            .SignWithHmac(hmacKey)
            .Build();

        KeyResolver resolver = kid => null;

        // Act
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.TryVerifyPresentation(sdJwt.ToPresentation(), resolver);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.KeyIdNotFound, result.Errors);
    }

    [Fact]
    public void VerifyPresentation_WithFallbackKey_UsesWhenNoKid()
    {
        // Arrange - Create SD-JWT WITHOUT key ID
        var hmacKey = _keyGen.GenerateHmacKey();

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("email", "alice@example.com")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .MakeSelective("email")
            .SignWithHmac(hmacKey)
            .Build();

        // Resolver for when kid IS present
        KeyResolver resolver = kid => throw new InvalidOperationException("Should not be called");

        // Act - Should use fallback key since no kid in JWT
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(sdJwt.ToPresentation(), resolver, fallbackKey: hmacKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyPresentation_NoResolverNoFallback_ThrowsArgumentException()
    {
        // Arrange - JWT with kid but no resolver or fallback
        var hmacKey = _keyGen.GenerateHmacKey();

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v1")
            .SignWithHmac(hmacKey)
            .Build();

        // Act & Assert
        var verifier = TestHelpers.CreateVerifier();
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(sdJwt.ToPresentation(), keyResolver: null, fallbackKey: null));

        Assert.Equal(ErrorCode.KeyResolverMissing, exception.ErrorCode);
    }

    [Fact]
    public void VerifyPresentation_KeyResolverThrowsException_FailsVerification()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v1")
            .SignWithHmac(hmacKey)
            .Build();

        // Resolver that throws
        KeyResolver resolver = kid => throw new InvalidOperationException("Database error");

        // Act & Assert
        var verifier = TestHelpers.CreateVerifier();
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(sdJwt.ToPresentation(), resolver));

        Assert.Equal(ErrorCode.KeyResolverFailed, exception.ErrorCode);
        Assert.Contains("resolver", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryVerifyPresentation_KeyResolverThrowsException_ReturnsInvalidResult()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v1")
            .SignWithHmac(hmacKey)
            .Build();

        KeyResolver resolver = kid => throw new InvalidOperationException("Database error");

        // Act
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.TryVerifyPresentation(sdJwt.ToPresentation(), resolver);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.KeyResolverFailed, result.Errors);
    }

    [Fact]
    public void VerifyPresentation_MultipleKeys_SelectsCorrectKey()
    {
        // Arrange - Create multiple JWTs with different keys
        var key1 = _keyGen.GenerateHmacKey();
        var key2 = _keyGen.GenerateHmacKey();
        var key3 = _keyGen.GenerateHmacKey();

        var sdJwt1 = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-1")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v1")
            .SignWithHmac(key1)
            .Build();

        var sdJwt2 = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-2")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v2")
            .SignWithHmac(key2)
            .Build();

        var sdJwt3 = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-3")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v3")
            .SignWithHmac(key3)
            .Build();

        // Resolver with multiple keys
        var keys = new Dictionary<string, byte[]>
        {
            ["key-v1"] = key1,
            ["key-v2"] = key2,
            ["key-v3"] = key3
        };
        KeyResolver resolver = kid => keys.GetValueOrDefault(kid);

        // Act - Verify each JWT uses correct key
        var verifier = TestHelpers.CreateVerifier();
        var result1 = verifier.VerifyPresentation(sdJwt1.ToPresentation(), resolver);
        var result2 = verifier.VerifyPresentation(sdJwt2.ToPresentation(), resolver);
        var result3 = verifier.VerifyPresentation(sdJwt3.ToPresentation(), resolver);

        // Assert - All should verify successfully
        Assert.True(result1.IsValid);
        Assert.True(result2.IsValid);
        Assert.True(result3.IsValid);
    }

    [Fact]
    public void VerifyPresentation_WrongKeyForKeyId_FailsVerification()
    {
        // Arrange - Sign with key1 but resolver returns key2
        var key1 = _keyGen.GenerateHmacKey();
        var key2 = _keyGen.GenerateHmacKey();

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v1")
            .SignWithHmac(key1)
            .Build();

        // Resolver returns wrong key
        KeyResolver resolver = kid => key2;

        // Act & Assert
        var verifier = TestHelpers.CreateVerifier();
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(sdJwt.ToPresentation(), resolver));

        Assert.Equal(ErrorCode.InvalidSignature, exception.ErrorCode);
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("RS256")]
    [InlineData("ES256")]
    public void VerifyPresentation_AllAlgorithms_ResolveKeyCorrectly(string algorithmName)
    {
        // Arrange
        byte[] signingKey;
        byte[] verificationKey;
        var keyId = $"key-{algorithmName}";

        switch (algorithmName)
        {
            case "HS256":
                signingKey = _keyGen.GenerateHmacKey();
                verificationKey = signingKey;
                break;
            case "RS256":
                (signingKey, verificationKey) = _keyGen.GenerateRsaKeyPair();
                break;
            case "ES256":
                (signingKey, verificationKey) = _keyGen.GenerateEcdsaKeyPair();
                break;
            default:
                throw new InvalidOperationException($"Unknown algorithm: {algorithmName}");
        }

        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId(keyId);

        var sdJwt = algorithmName switch
        {
            "HS256" => builder.SignWithHmac(signingKey).Build(),
            "RS256" => builder.SignWithRsa(signingKey).Build(),
            "ES256" => builder.SignWithEcdsa(signingKey).Build(),
            _ => throw new InvalidOperationException()
        };

        // Resolver
        KeyResolver resolver = kid => kid == keyId ? verificationKey : null;

        // Act
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(sdJwt.ToPresentation(), resolver);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyPresentation_NullResolver_WithFallbackKey_Succeeds()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();

        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(hmacKey)
            .Build();

        // Act - Null resolver but with fallback (backward compat)
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(sdJwt.ToPresentation(), keyResolver: null, fallbackKey: hmacKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyPresentation_KidWithControlCharacters_FailsBeforeResolver()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();
        var presentation = CreatePresentationWithCustomKid("key-\u0001-invalid");

        var resolverCalled = false;
        KeyResolver resolver = kid =>
        {
            resolverCalled = true;
            return hmacKey;
        };

        var verifier = TestHelpers.CreateVerifier();

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, resolver));

        Assert.Equal(ErrorCode.KeyIdInvalidCharacters, exception.ErrorCode);
        Assert.False(resolverCalled);
    }

    [Fact]
    public void TryVerifyPresentation_KeyIdTooLong_ReturnsInvalidResult()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();
        var longKid = new string('k', 300);
        var presentation = CreatePresentationWithCustomKid(longKid);

        var resolverCalled = false;
        KeyResolver resolver = kid =>
        {
            resolverCalled = true;
            return hmacKey;
        };

        var verifier = TestHelpers.CreateVerifier();

        // Act
        var result = verifier.TryVerifyPresentation(presentation, resolver);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.KeyIdTooLong, result.Errors);
        Assert.False(resolverCalled);
    }

    private static string CreatePresentationWithCustomKid(string keyId)
    {
        var headerJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["alg"] = "HS256",
            ["kid"] = keyId
        });

        var payloadJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            ["_sd"] = Array.Empty<string>(),
            ["_sd_alg"] = "sha-256"
        });

        var header = Base64UrlEncoder.Encode(headerJson);
        var payload = Base64UrlEncoder.Encode(payloadJson);
        var signature = Base64UrlEncoder.Encode("sig");

        var jwt = $"{header}.{payload}.{signature}";
        return $"{jwt}~";
    }
}
