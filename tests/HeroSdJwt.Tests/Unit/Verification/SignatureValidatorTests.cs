using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for SignatureValidator.
/// Tests JWT signature verification for HS256, RS256, and ES256 algorithms.
/// </summary>
public class SignatureValidatorTests
{
    [Fact]
    public void VerifyJwtSignature_WithValidHs256Signature_ReturnsTrue()
    {
        // Arrange
        var key = GenerateHmacKey();
        var jwt = CreateSignedJwt("HS256", key, new { sub = "user123" });

        // Act
        var result = SignatureValidator.VerifyJwtSignature(jwt, key);

        // Assert
        Assert.True(result, "Valid HS256 signature should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_WithInvalidHs256Signature_ReturnsFalse()
    {
        // Arrange
        var key = GenerateHmacKey();
        var wrongKey = GenerateHmacKey();
        var jwt = CreateSignedJwt("HS256", key, new { sub = "user123" });

        // Act
        var result = SignatureValidator.VerifyJwtSignature(jwt, wrongKey);

        // Assert
        Assert.False(result, "Invalid HS256 signature should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_WithValidRs256Signature_ReturnsTrue()
    {
        // Arrange
        using var rsa = RSA.Create(2048); // 2048-bit key
        var privateKey = rsa.ExportRSAPrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = CreateSignedJwt("RS256", privateKey, new { sub = "user123" }, useRsa: true);

        // Act
        var result = SignatureValidator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "Valid RS256 signature should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_WithInvalidRs256Signature_ReturnsFalse()
    {
        // Arrange
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048); // Different key
        var privateKey = rsa1.ExportRSAPrivateKey();
        var wrongPublicKey = rsa2.ExportSubjectPublicKeyInfo();
        var jwt = CreateSignedJwt("RS256", privateKey, new { sub = "user123" }, useRsa: true);

        // Act
        var result = SignatureValidator.VerifyJwtSignature(jwt, wrongPublicKey);

        // Assert
        Assert.False(result, "Invalid RS256 signature should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_WithWeakRsaKey_ThrowsSdJwtException()
    {
        // Arrange - Create a weak 1024-bit RSA key (below minimum)
        using var rsa = RSA.Create(1024);
        var privateKey = rsa.ExportRSAPrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var jwt = CreateSignedJwt("RS256", privateKey, new { sub = "user123" }, useRsa: true);

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, publicKey));
        Assert.Contains("2048", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_WithValidEs256Signature_ReturnsTrue()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportECPrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = CreateSignedJwt("ES256", privateKey, new { sub = "user123" }, useEcdsa: true);

        // Act
        var result = SignatureValidator.VerifyJwtSignature(jwt, publicKey);

        // Assert
        Assert.True(result, "Valid ES256 signature should verify successfully");
    }

    [Fact]
    public void VerifyJwtSignature_WithInvalidEs256Signature_ReturnsFalse()
    {
        // Arrange
        using var ecdsa1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecdsa2 = ECDsa.Create(ECCurve.NamedCurves.nistP256); // Different key
        var privateKey = ecdsa1.ExportECPrivateKey();
        var wrongPublicKey = ecdsa2.ExportSubjectPublicKeyInfo();
        var jwt = CreateSignedJwt("ES256", privateKey, new { sub = "user123" }, useEcdsa: true);

        // Act
        var result = SignatureValidator.VerifyJwtSignature(jwt, wrongPublicKey);

        // Assert
        Assert.False(result, "Invalid ES256 signature should fail verification");
    }

    [Fact]
    public void VerifyJwtSignature_WithWrongCurve_ThrowsSdJwtException()
    {
        // Arrange - Use P-384 instead of required P-256 for ES256
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportECPrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = CreateSignedJwt("ES256", privateKey, new { sub = "user123" }, useEcdsa: true);

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, publicKey));
        Assert.Contains("P-256", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_WithNoneAlgorithm_ThrowsAlgorithmConfusionException()
    {
        // Arrange
        var jwt = CreateUnsignedJwt(new { sub = "user123" });
        var key = GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<AlgorithmConfusionException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, key));
        Assert.Contains("none", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void VerifyJwtSignature_WithNoneAlgorithmCaseVariants_ThrowsAlgorithmConfusionException()
    {
        // Test case-insensitive "none" algorithm detection
        var testCases = new[] { "none", "None", "NONE", "nOnE" };
        var key = GenerateHmacKey();

        foreach (var noneVariant in testCases)
        {
            // Arrange
            var jwt = CreateJwtWithAlgorithm(noneVariant, new { sub = "user123" });

            // Act & Assert
            Assert.Throws<AlgorithmConfusionException>(() =>
                SignatureValidator.VerifyJwtSignature(jwt, key));
        }
    }

    [Fact]
    public void VerifyJwtSignature_WithUnsupportedAlgorithm_ThrowsAlgorithmNotSupportedException()
    {
        // Arrange
        var jwt = CreateJwtWithAlgorithm("HS512", new { sub = "user123" });
        var key = GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<AlgorithmNotSupportedException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, key));
        Assert.Contains("HS512", exception.Message);
    }

    [Fact]
    public void VerifyJwtSignature_WithMalformedJwt_ThrowsSdJwtException()
    {
        // Arrange - JWT with only 2 parts instead of 3
        var malformedJwt = "header.payload";
        var key = GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            SignatureValidator.VerifyJwtSignature(malformedJwt, key));
        Assert.Contains("3 parts", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_WithMissingAlgClaim_ThrowsSdJwtException()
    {
        // Arrange
        var header = new { typ = "JWT" }; // Missing 'alg' claim
        var payload = new { sub = "user123" };
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);
        var headerBase64 = Base64UrlEncode(headerJson);
        var payloadBase64 = Base64UrlEncode(payloadJson);
        var jwt = $"{headerBase64}.{payloadBase64}.signature";

        var key = GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, key));
        Assert.Contains("alg", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_WithEmptyAlgClaim_ThrowsSdJwtException()
    {
        // Arrange
        var jwt = CreateJwtWithAlgorithm("", new { sub = "user123" });
        var key = GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, key));
        Assert.Contains("empty", exception.Message);
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_WithNullJwt_ThrowsArgumentNullException()
    {
        // Arrange
        var key = GenerateHmacKey();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SignatureValidator.VerifyJwtSignature(null!, key));
    }

    [Fact]
    public void VerifyJwtSignature_WithNullKey_ThrowsArgumentNullException()
    {
        // Arrange
        var key = GenerateHmacKey();
        var jwt = CreateSignedJwt("HS256", key, new { sub = "user123" });

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SignatureValidator.VerifyJwtSignature(jwt, null!));
    }

    [Fact]
    public void VerifyJwtSignature_WithTamperedPayload_ReturnsFalse()
    {
        // Arrange
        var key = GenerateHmacKey();
        var jwt = CreateSignedJwt("HS256", key, new { sub = "user123" });

        // Tamper with payload
        var parts = jwt.Split('.');
        var tamperedPayload = Base64UrlEncode(JsonSerializer.Serialize(new { sub = "hacker" }));
        var tamperedJwt = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        // Act
        var result = SignatureValidator.VerifyJwtSignature(tamperedJwt, key);

        // Assert
        Assert.False(result, "Tampered payload should fail signature verification");
    }

    [Fact]
    public void VerifyJwtSignature_WithTamperedHeader_ReturnsFalse()
    {
        // Arrange
        var key = GenerateHmacKey();
        var jwt = CreateSignedJwt("HS256", key, new { sub = "user123" });

        // Tamper with header
        var parts = jwt.Split('.');
        var tamperedHeader = Base64UrlEncode(JsonSerializer.Serialize(new { alg = "HS256", typ = "TAMPERED" }));
        var tamperedJwt = $"{tamperedHeader}.{parts[1]}.{parts[2]}";

        // Act
        var result = SignatureValidator.VerifyJwtSignature(tamperedJwt, key);

        // Assert
        Assert.False(result, "Tampered header should fail signature verification");
    }

    // Helper methods

    private static byte[] GenerateHmacKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private static string CreateSignedJwt(string algorithm, byte[] key, object payload, bool useRsa = false, bool useEcdsa = false)
    {
        var header = new { alg = algorithm, typ = "JWT" };
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerBase64 = Base64UrlEncode(headerJson);
        var payloadBase64 = Base64UrlEncode(payloadJson);
        var signingInput = $"{headerBase64}.{payloadBase64}";

        byte[] signature;

        if (useRsa)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(key, out _);
            signature = rsa.SignData(System.Text.Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else if (useEcdsa)
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(key, out _);
            signature = ecdsa.SignData(System.Text.Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256);
        }
        else // HMAC
        {
            using var hmac = new HMACSHA256(key);
            signature = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signingInput));
        }

        var signatureBase64 = Base64UrlEncode(signature);
        return $"{signingInput}.{signatureBase64}";
    }

    private static string CreateUnsignedJwt(object payload)
    {
        var header = new { alg = "none", typ = "JWT" };
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerBase64 = Base64UrlEncode(headerJson);
        var payloadBase64 = Base64UrlEncode(payloadJson);

        return $"{headerBase64}.{payloadBase64}.";
    }

    private static string CreateJwtWithAlgorithm(string algorithm, object payload)
    {
        var header = new { alg = algorithm, typ = "JWT" };
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerBase64 = Base64UrlEncode(headerJson);
        var payloadBase64 = Base64UrlEncode(payloadJson);

        return $"{headerBase64}.{payloadBase64}.fakesignature";
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
