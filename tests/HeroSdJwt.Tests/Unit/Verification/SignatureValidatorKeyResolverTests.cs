using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for SignatureValidator with key resolver support.
/// </summary>
public class SignatureValidatorKeyResolverTests
{
    private readonly KeyGenerator _keyGen = KeyGenerator.Instance;
    private readonly JwtSigner _signer = new();
    private readonly SignatureValidator _validator = new();

    [Fact]
    public void VerifyJwtSignature_WithResolver_ExtractsKidAndResolvesKey()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "test-key-123";
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        var keys = new Dictionary<string, byte[]> { [keyId] = _hmacKey };
        KeyResolver resolver = kid => keys.GetValueOrDefault(kid);

        // Act
        var isValid = _validator.VerifyJwtSignature(jwt, resolver);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyJwtSignature_NoKidInJwt_UsesFallbackKey()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256);

        KeyResolver resolver = kid => throw new InvalidOperationException("Should not be called");

        // Act
        var isValid = _validator.VerifyJwtSignature(jwt, resolver, fallbackKey: _hmacKey);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyJwtSignature_KidPresentResolverReturnsNull_ThrowsException()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "unknown-key";
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        KeyResolver resolver = kid => null; // Returns null for unknown key

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, resolver));

        Assert.Equal(ErrorCode.KeyIdNotFound, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_KidPresentNoResolverNoFallback_ThrowsException()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "key-123";
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, keyResolver: null, fallbackKey: null));

        Assert.Equal(ErrorCode.KeyResolverMissing, exception.ErrorCode);
    }

    [Fact]
    public void VerifyJwtSignature_ResolverThrowsException_WrapsInKeyResolverFailed()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "key-123";
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        KeyResolver resolver = kid => throw new InvalidOperationException("Database connection failed");

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, resolver));

        Assert.Equal(ErrorCode.KeyResolverFailed, exception.ErrorCode);
        Assert.Contains("resolver", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void VerifyJwtSignature_ResolverReturnsWrongKey_ReturnsFalse()
    {
        // Arrange
        var key1 = _keyGen.GenerateHmacKey();
        var key2 = _keyGen.GenerateHmacKey();
        var keyId = "key-1";
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, key1, SignatureAlgorithm.HS256, keyId);

        KeyResolver resolver = kid => key2; // Returns wrong key

        // Act
        var isValid = _validator.VerifyJwtSignature(jwt, resolver);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void VerifyJwtSignature_NoKidNoResolverWithFallback_UsesFallback()
    {
        // Arrange
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256);

        // Act - No kid, no resolver, but fallback provided (backward compat)
        var isValid = _validator.VerifyJwtSignature(jwt, keyResolver: null, fallbackKey: _hmacKey);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyJwtSignature_WithResolver_ValidatesKeyIdFormat()
    {
        // Arrange - Create JWT with valid kid
        var _hmacKey = _keyGen.GenerateHmacKey();
        var keyId = "valid-key-id";
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256, keyId);

        KeyResolver resolver = kid =>
        {
            // Resolver should receive the exact keyId
            Assert.Equal(keyId, kid);
            return _hmacKey;
        };

        // Act
        var isValid = _validator.VerifyJwtSignature(jwt, resolver);

        // Assert
        Assert.True(isValid);
    }

    [Theory]
    [InlineData("HS256")]
    [InlineData("RS256")]
    [InlineData("ES256")]
    public void VerifyJwtSignature_AllAlgorithms_WorkWithResolver(string algorithmName)
    {
        // Arrange
        SignatureAlgorithm algorithm;
        byte[] signingKey;
        byte[] verificationKey;
        var keyId = $"key-{algorithmName}";

        switch (algorithmName)
        {
            case "HS256":
                algorithm = SignatureAlgorithm.HS256;
                signingKey = _keyGen.GenerateHmacKey();
                verificationKey = signingKey;
                break;
            case "RS256":
                algorithm = SignatureAlgorithm.RS256;
                (signingKey, verificationKey) = _keyGen.GenerateRsaKeyPair();
                break;
            case "ES256":
                algorithm = SignatureAlgorithm.ES256;
                (signingKey, verificationKey) = _keyGen.GenerateEcdsaKeyPair();
                break;
            default:
                throw new ArgumentException($"Unknown algorithm: {algorithmName}");
        }

        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };
        var jwt = _signer.CreateJwt(payload, signingKey, algorithm, keyId);

        KeyResolver resolver = kid => kid == keyId ? verificationKey : null;

        // Act
        var isValid = _validator.VerifyJwtSignature(jwt, resolver);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyJwtSignature_BackwardCompatibility_OldSignatureStillWorks()
    {
        // Arrange - Use old signature (direct key, no resolver)
        var _hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };

        var jwt = _signer.CreateJwt(payload, _hmacKey, SignatureAlgorithm.HS256);

        // Act - Old method signature (should still work)
        var isValid = _validator.VerifyJwtSignature(jwt, _hmacKey);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyJwtSignature_KidWithControlCharacters_Throws()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };
        var keyId = "key-\u0001-invalid";

        var jwt = _signer.CreateJwt(payload, hmacKey, SignatureAlgorithm.HS256, keyId);

        var resolverCalled = false;
        KeyResolver resolver = kid =>
        {
            resolverCalled = true;
            return hmacKey;
        };

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, resolver));

        Assert.Equal(ErrorCode.KeyIdInvalidCharacters, exception.ErrorCode);
        Assert.False(resolverCalled);
    }

    [Fact]
    public void VerifyJwtSignature_KeyIdTooLong_ThrowsBeforeResolver()
    {
        // Arrange
        var hmacKey = _keyGen.GenerateHmacKey();
        var payload = new Dictionary<string, object> { ["sub"] = "user-123" };
        var keyId = new string('k', 300);

        var jwt = _signer.CreateJwt(payload, hmacKey, SignatureAlgorithm.HS256, keyId);

        var resolverCalled = false;
        KeyResolver resolver = kid =>
        {
            resolverCalled = true;
            return hmacKey;
        };

        // Act & Assert
        var exception = Assert.Throws<SdJwtException>(() =>
            _validator.VerifyJwtSignature(jwt, resolver));

        Assert.Equal(ErrorCode.KeyIdTooLong, exception.ErrorCode);
        Assert.False(resolverCalled);
    }
}
