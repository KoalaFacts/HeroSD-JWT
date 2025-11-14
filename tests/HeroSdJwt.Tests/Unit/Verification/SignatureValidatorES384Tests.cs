using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for SignatureValidator with ES384 algorithm.
/// Tests ECDSA with P-384 curve and SHA-384 signature verification.
/// </summary>
public class SignatureValidatorES384Tests
{
    private readonly SignatureValidator _validator = new();
    private readonly JwtSigner _signer = new();

    [Fact]
    public void VerifyJwtSignature_ValidES384Signature_ReturnsTrue()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "Valid ES384 signature should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_TamperedPayload_ReturnsFalse()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

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
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Tamper with header
        var parts = jwt.Split('.');
        var tamperedHeader = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = "ES384", typ = "TAMPERED" }));
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
        using var ecdsa1 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var ecdsa2 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa1.ExportPkcs8PrivateKey();
        var wrongPublicKey = ecdsa2.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, wrongPublicKey);

        // Assert
        Assert.False(result, "Invalid ES384 signature with wrong key should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_WrongCurveP256_ThrowsSdJwtException()
    {
        // Arrange - Use P-256 instead of required P-384 for ES384
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, publicKey));
        Assert.Contains("P-384", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_WrongCurveP521_ThrowsSdJwtException()
    {
        // Arrange - Use P-521 instead of required P-384 for ES384
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, publicKey));
        Assert.Contains("P-384", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_P384Curve_VerifiesSuccessfully()
    {
        // Arrange - Explicitly test P-384 curve validation
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Act
        var result = _validator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "P-384 curve should verify successfully for ES384");
    }

    [Fact]
    public void VerifyJwtSignature_NullJwt_ThrowsArgumentNullException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _validator.VerifyJwtSignature(null!, publicKey));
    }

    [Fact]
    public void VerifyJwtSignature_NullKey_ThrowsArgumentNullException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportECPrivateKey();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _validator.VerifyJwtSignature(jwt, null!));
    }

    [Fact]
    public void VerifyJwtSignature_EmptyKey_ThrowsException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportECPrivateKey();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);
        var emptyKey = Array.Empty<byte>();

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            _validator.VerifyJwtSignature(jwt, emptyKey));
    }

    [Fact]
    public void VerifyJwtSignature_MultipleValidations_ConsistentResults()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = "user123" }, privateKey, SignatureAlgorithm.ES384);

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
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var smallPayload = new { sub = "u" };
        var mediumPayload = new { sub = "user123", iss = "https://example.com", aud = "test-audience" };
        var largePayload = new {
            sub = "user123",
            iss = "https://example.com",
            aud = "test-audience",
            claims = new[] { "claim1", "claim2", "claim3", "claim4", "claim5" }
        };

        var jwtSmall = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = smallPayload.sub }, privateKey, SignatureAlgorithm.ES384);
        var jwtMedium = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = mediumPayload.sub, ["iss"] = mediumPayload.iss, ["aud"] = mediumPayload.aud }, privateKey, SignatureAlgorithm.ES384);
        var jwtLarge = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = largePayload.sub, ["iss"] = largePayload.iss, ["aud"] = largePayload.aud, ["claims"] = largePayload.claims }, privateKey, SignatureAlgorithm.ES384);

        // Act
        var resultSmall = _validator.VerifyJwtSignature(jwtSmall, publicKey);
        var resultMedium = _validator.VerifyJwtSignature(jwtMedium, publicKey);
        var resultLarge = _validator.VerifyJwtSignature(jwtLarge, publicKey);

        // Assert
        Assert.True(resultSmall, "Small payload should verify successfully");
        Assert.True(resultMedium, "Medium payload should verify successfully");
        Assert.True(resultLarge, "Large payload should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_NonDeterministicSignatures_BothVerify()
    {
        // Arrange - ECDSA signatures are non-deterministic, same input produces different signatures
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var payload = new { sub = "user123" };
        var jwt1 = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = payload.sub }, privateKey, SignatureAlgorithm.ES384);
        var jwt2 = _signer.CreateJwt(new Dictionary<string, object> { ["sub"] = payload.sub }, privateKey, SignatureAlgorithm.ES384);

        // The signatures should be different
        Assert.NotEqual(jwt1, jwt2);

        // Act - Both should verify successfully
        var result1 = _validator.VerifyJwtSignature(jwt1, publicKey);
        var result2 = _validator.VerifyJwtSignature(jwt2, publicKey);

        // Assert
        Assert.True(result1, "First ES384 signature should verify successfully");
        Assert.True(result2, "Second ES384 signature should verify successfully");
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
