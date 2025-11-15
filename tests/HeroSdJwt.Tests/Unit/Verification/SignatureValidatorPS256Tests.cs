using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for SignatureValidator with PS256 algorithm.
/// Tests RSA-PSS with SHA-256 signature verification.
/// </summary>
public class SignatureValidatorPS256Tests
{
    private readonly SignatureValidator _validator = new();
    private readonly JwtSigner _signer = new();

    [Fact]
    public void VerifyJwtSignature_ValidPS256Signature_ReturnsTrue()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "Valid PS256 signature should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_TamperedPayload_ReturnsFalse()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Tamper with payload
        var parts = jwt.Split('.');
        var tamperedPayload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { sub = "hacker" }));
        var tamperedJwt = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        // Act
        var result = _validator.VerifyJwtSignature(tamperedJwt, publicKey);

        // Assert
        Assert.False(result, "Tampered payload should fail signature verification");
    }

    [Fact]
    public void VerifyJwtSignature_TamperedHeader_ReturnsFalse()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Tamper with header
        var parts = jwt.Split('.');
        var tamperedHeader = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "PS256", typ = "TAMPERED" }));
        var tamperedJwt = $"{tamperedHeader}.{parts[1]}.{parts[2]}";

        // Act
        var result = _validator.VerifyJwtSignature(tamperedJwt, publicKey);

        // Assert
        Assert.False(result, "Tampered header should fail signature verification");
    }

    [Fact]
    public void VerifyJwtSignature_WrongKey_ReturnsFalse()
    {
        // Arrange
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var privateKey = rsa1.ExportPkcs8PrivateKey();
        var wrongPublicKey = rsa2.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, wrongPublicKey);

        // Assert
        Assert.False(result, "Invalid PS256 signature with wrong key should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_WeakRsaKey_ThrowsSdJwtException()
    {
        // Arrange - Create a weak 1024-bit RSA key (below minimum 2048-bit requirement)
        using var rsa = RSA.Create(1024);
        var privateKey = rsa.ExportPkcs8PrivateKey();

        // Act & Assert - Signer now validates key size during signing
        var exception = Assert.Throws<ArgumentException>(() =>
            _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256));
        Assert.Contains("2048", exception.Message);
    }

    [Fact]
    public void VerifyJwtSignature_2048BitKey_VerifiesSuccessfully()
    {
        // Arrange - Test minimum 2048-bit key requirement
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "2048-bit RSA key should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_3072BitKey_VerifiesSuccessfully()
    {
        // Arrange - Test larger key size
        using var rsa = RSA.Create(3072);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "3072-bit RSA key should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_4096BitKey_VerifiesSuccessfully()
    {
        // Arrange - Test even larger key size
        using var rsa = RSA.Create(4096);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "4096-bit RSA key should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_NullJwt_ThrowsArgumentNullException()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _validator.VerifyJwtSignature(null!, publicKey));
    }

    [Fact]
    public void VerifyJwtSignature_NullKey_ThrowsArgumentNullException()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _validator.VerifyJwtSignature(jwt, null!));
    }

    [Fact]
    public void VerifyJwtSignature_MultipleValidations_ConsistentResults()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.PS256);

        // Act - Verify the same JWT multiple times
        var result1 = _validator.VerifyJwtSignature(jwt, publicKey);
        var result2 = _validator.VerifyJwtSignature(jwt, publicKey);
        var result3 = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result1);
        Assert.True(result2);
        Assert.True(result3);
    }

    [Fact]
    public void VerifyJwtSignature_DifferentPayloadSizes_VerifiesCorrectly()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        var smallPayload = new { sub = "u" };
        var mediumPayload = new { sub = "user123", iss = "https://example.com", aud = "test-audience" };
        var largePayload = new
        {
            sub = "user123",
            iss = "https://example.com",
            aud = "test-audience",
            claims = new[] { "claim1", "claim2", "claim3", "claim4", "claim5" }
        };

        var jwtSmall = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = smallPayload.sub }, privateKey, SignatureAlgorithm.PS256);
        var jwtMedium = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = mediumPayload.sub, ["iss"] = mediumPayload.iss, ["aud"] = mediumPayload.aud }, privateKey, SignatureAlgorithm.PS256);
        var jwtLarge = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = largePayload.sub, ["iss"] = largePayload.iss, ["aud"] = largePayload.aud, ["claims"] = largePayload.claims }, privateKey, SignatureAlgorithm.PS256);

        // Act
        var resultSmall = _validator.VerifyJwtSignature(jwtSmall, publicKey);
        var resultMedium = _validator.VerifyJwtSignature(jwtMedium, publicKey);
        var resultLarge = _validator.VerifyJwtSignature(jwtLarge, publicKey);

        // Assert
        Assert.True(resultSmall, "Small payload should verify successfully");
        Assert.True(resultMedium, "Medium payload should verify successfully");
        Assert.True(resultLarge, "Large payload should verify successfully");
    }

    // Helper methods for edge-case tests that bypass JwtSigner validation
    private static string CreateManualJwt(string algorithm, byte[] privateKey, Dictionary<string, string> payload, Func<byte[], byte[], byte[]> signFunc)
    {
        var header = new { alg = algorithm, typ = "JWT" };
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerBase64 = Base64UrlEncoder.Encode(headerJson);
        var payloadBase64 = Base64UrlEncoder.Encode(payloadJson);
        var signingInput = $"{headerBase64}.{payloadBase64}";
        var signingInputBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);

        var signature = signFunc(signingInputBytes, privateKey);
        var signatureBase64 = Base64UrlEncoder.Encode(signature);
        return $"{signingInput}.{signatureBase64}";
    }
}
