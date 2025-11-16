using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for JwtSigner.CreateJwt with key ID parameter.
/// </summary>
public class JwtSignerKeyIdTests
{
    private readonly KeyGenerator _keyGen = KeyGenerator.Instance;
    private readonly JwtSigner _signer = new();

    [Fact]
    public void CreateJwt_WithKeyId_IncludesKidInHeader()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        var keyId = "test-key-2024";

        // Act
        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        // Assert
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(keyId, kidElement.GetString());
    }

    [Fact]
    public void CreateJwt_WithoutKeyId_NoKidInHeader()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        // Act
        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256);

        // Assert
        var parts = jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.False(header.TryGetProperty("kid", out _)); // kid should not be present
    }

    [Fact]
    public void CreateJwt_WithNullKeyId_NoKidInHeader()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };

        // Act
        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, null);

        // Assert
        var parts = jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.False(header.TryGetProperty("kid", out _));
    }

    [Fact]
    public void CreateJwt_WithEmptyKeyId_NoKidInHeader()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };

        // Act
        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, "");

        // Assert
        var parts = jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.False(header.TryGetProperty("kid", out _));
    }

    [Fact]
    public void CreateJwt_WithWhitespaceKeyId_NoKidInHeader()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };

        // Act
        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, "   ");

        // Assert
        var parts = jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.False(header.TryGetProperty("kid", out _));
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("RS256")]
    [InlineData("ES256")]
    public void CreateJwt_WithKeyIdAllAlgorithms_IncludesKid(string algorithmName)
    {
        // Arrange
        var algorithm = algorithmName switch
        {
            "HS256" => SignatureAlgorithm.HS256,
            "RS256" => SignatureAlgorithm.RS256,
            "ES256" => SignatureAlgorithm.ES256,
            _ => throw new ArgumentException($"Unknown algorithm: {algorithmName}")
        };

        byte[] signingKey = algorithm switch
        {
            SignatureAlgorithm.HS256 => _keyGen.GenerateHmacKey(),
            SignatureAlgorithm.RS256 => _keyGen.GenerateRsaKeyPair().PrivateKey,
            SignatureAlgorithm.ES256 => _keyGen.GenerateEcdsaKeyPair().PrivateKey,
            _ => throw new ArgumentException()
        };

        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };
        var keyId = $"test-key-{algorithmName}";

        // Act
        var jwt = _signer.CreateJwt(payload, signingKey, algorithm, keyId);

        // Assert
        var parts = jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("kid", out var kidElement));
        Assert.Equal(keyId, kidElement.GetString());
        Assert.True(header.TryGetProperty("alg", out var algElement));
        Assert.Equal(algorithmName, algElement.GetString());
    }

    [Fact]
    public void CreateJwt_WithKeyIdAndOtherClaims_PreservesAllClaims()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["iss"] = "https://issuer.example.com",
            ["aud"] = "https://audience.example.com",
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };
        var keyId = "test-key";

        // Act
        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        // Assert - Verify JWT is valid and contains all claims
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        var payloadJson = Base64UrlEncoder.DecodeString(parts[1]);
        var claims = JsonDocument.Parse(payloadJson).RootElement;

        Assert.Equal("user-123", claims.GetProperty("sub").GetString());
        Assert.Equal("https://issuer.example.com", claims.GetProperty("iss").GetString());

        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;
        Assert.Equal(keyId, header.GetProperty("kid").GetString());
    }
}
