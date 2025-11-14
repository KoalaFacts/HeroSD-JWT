using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for SignatureValidator with HS384 algorithm.
/// Tests HMAC-SHA384 signature verification.
/// </summary>
public class SignatureValidatorHS384Tests
{
    private readonly SignatureValidator _validator = new();
    private readonly JwtSigner _signer = new();

    [Fact]
    public void VerifyJwtSignature_ValidHS384Signature_ReturnsTrue()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, key);

        // Assert
        Assert.True(result, "Valid HS384 signature should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_TamperedPayload_ReturnsFalse()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);

        // Tamper with payload
        var parts = jwt.Split('.');
        var tamperedPayload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { sub = "hacker" }));
        var tamperedJwt = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        // Act
        var result = _validator.VerifyJwtSignature(tamperedJwt, key);

        // Assert
        Assert.False(result, "Tampered payload should fail signature verification");
    }

    [Fact]
    public void VerifyJwtSignature_TamperedHeader_ReturnsFalse()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);

        // Tamper with header
        var parts = jwt.Split('.');
        var tamperedHeader = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "HS384", typ = "TAMPERED" }));
        var tamperedJwt = $"{tamperedHeader}.{parts[1]}.{parts[2]}";

        // Act
        var result = _validator.VerifyJwtSignature(tamperedJwt, key);

        // Assert
        Assert.False(result, "Tampered header should fail signature verification");
    }

    [Fact]
    public void VerifyJwtSignature_WrongKey_ReturnsFalse()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var wrongKey = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, wrongKey);

        // Assert
        Assert.False(result, "Invalid HS384 signature with wrong key should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_InvalidSignatureLength_ReturnsFalse()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var header = new { alg = "HS384", typ = "JWT" };
        var payload = new { sub = "user123" };
        var headerBase64 = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header));
        var payloadBase64 = Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));

        // Create JWT with invalid signature length (too short)
        var invalidSignature = Base64UrlEncoder.Encode(new byte[32]); // 32 bytes instead of 48
        var jwt = $"{headerBase64}.{payloadBase64}.{invalidSignature}";

        // Act
        var result = _validator.VerifyJwtSignature(jwt, key);

        // Assert
        Assert.False(result, "Signature with incorrect length should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_NullJwt_ThrowsArgumentNullException()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _validator.VerifyJwtSignature(null!, key));
    }

    [Fact]
    public void VerifyJwtSignature_NullKey_ThrowsArgumentNullException()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _validator.VerifyJwtSignature(jwt, null!));
    }

    [Fact]
    public void VerifyJwtSignature_EmptyKey_ThrowsException()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);
        var emptyKey = Array.Empty<byte>();

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            _validator.VerifyJwtSignature(jwt, emptyKey));
    }

    [Fact]
    public void VerifyJwtSignature_EmptySignature_ReturnsFalse()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var header = new { alg = "HS384", typ = "JWT" };
        var payload = new { sub = "user123" };
        var headerBase64 = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header));
        var payloadBase64 = Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload));
        var jwt = $"{headerBase64}.{payloadBase64}.";

        // Act & Assert
        // Empty signature should either return false or throw exception
        try
        {
            var result = _validator.VerifyJwtSignature(jwt, key);
            Assert.False(result, "Empty signature should fail verification");
        }
        catch (SdJwtException)
        {
            // Also acceptable to throw exception
        }
    }

    [Fact]
    public void VerifyJwtSignature_MultipleValidations_ConsistentResults()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, key, SignatureAlgorithm.HS384);

        // Act - Verify the same JWT multiple times
        var result1 = _validator.VerifyJwtSignature(jwt, key);
        var result2 = _validator.VerifyJwtSignature(jwt, key);
        var result3 = _validator.VerifyJwtSignature(jwt, key);

        // Assert
        Assert.True(result1);
        Assert.True(result2);
        Assert.True(result3);
    }

    [Fact]
    public void VerifyJwtSignature_DifferentPayloadSizes_VerifiesCorrectly()
    {
        // Arrange
        var key = RandomNumberGenerator.GetBytes(48);

        var smallPayload = new { sub = "u" };
        var mediumPayload = new { sub = "user123", iss = "https://example.com", aud = "test-audience" };
        var largePayload = new {
            sub = "user123",
            iss = "https://example.com",
            aud = "test-audience",
            claims = new[] { "claim1", "claim2", "claim3", "claim4", "claim5" }
        };

        var jwtSmall = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = smallPayload.sub }, key, SignatureAlgorithm.HS384);
        var jwtMedium = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = mediumPayload.sub, ["iss"] = mediumPayload.iss, ["aud"] = mediumPayload.aud }, key, SignatureAlgorithm.HS384);
        var jwtLarge = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = largePayload.sub, ["iss"] = largePayload.iss, ["aud"] = largePayload.aud, ["claims"] = largePayload.claims }, key, SignatureAlgorithm.HS384);

        // Act
        var resultSmall = _validator.VerifyJwtSignature(jwtSmall, key);
        var resultMedium = _validator.VerifyJwtSignature(jwtMedium, key);
        var resultLarge = _validator.VerifyJwtSignature(jwtLarge, key);

        // Assert
        Assert.True(resultSmall, "Small payload should verify successfully");
        Assert.True(resultMedium, "Medium payload should verify successfully");
        Assert.True(resultLarge, "Large payload should verify successfully");
    }

}
