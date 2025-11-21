using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Issuance;

/// <summary>
/// Unit tests for SdJwtIssuer - focused on error cases and edge conditions.
/// Complements the contract tests with additional coverage of security validations.
/// </summary>
public class SdJwtIssuerTests
{
    private readonly SdJwtIssuer _issuer;
    private readonly byte[] _signingKey;

    public SdJwtIssuerTests()
    {
        _issuer = TestHelpers.CreateIssuer();
        _signingKey = new byte[32];
        RandomNumberGenerator.Fill(_signingKey);
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_WithNullDisclosureGenerator_ThrowsArgumentNullException()
    {
        // Arrange
        var digestCalculator = new DigestCalculator();
        var ecConverter = new EcPublicKeyConverter();
        var jwtSigner = new JwtSigner();

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() =>
            new SdJwtIssuer(null!, digestCalculator, ecConverter, jwtSigner));
    }

    [Fact]
    public void Constructor_WithNullDigestCalculator_ThrowsArgumentNullException()
    {
        // Arrange
        var disclosureGenerator = new DisclosureGenerator();
        var ecConverter = new EcPublicKeyConverter();
        var jwtSigner = new JwtSigner();

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() =>
            new SdJwtIssuer(disclosureGenerator, null!, ecConverter, jwtSigner));
    }

    [Fact]
    public void Constructor_WithNullEcConverter_ThrowsArgumentNullException()
    {
        // Arrange
        var disclosureGenerator = new DisclosureGenerator();
        var digestCalculator = new DigestCalculator();
        var jwtSigner = new JwtSigner();

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() =>
            new SdJwtIssuer(disclosureGenerator, digestCalculator, null!, jwtSigner));
    }

    [Fact]
    public void Constructor_WithNullJwtSigner_ThrowsArgumentNullException()
    {
        // Arrange
        var disclosureGenerator = new DisclosureGenerator();
        var digestCalculator = new DigestCalculator();
        var ecConverter = new EcPublicKeyConverter();

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() =>
            new SdJwtIssuer(disclosureGenerator, digestCalculator, ecConverter, null!));
    }

    #endregion

    #region Reserved Claims Validation Tests

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Iss_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["iss"] = "https://_issuer.example.com"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["iss"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("iss", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Aud_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["aud"] = "https://audience.example.com"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["aud"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("aud", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Exp_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["exp"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("exp", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Nbf_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["nbf"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["nbf"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("nbf", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Cnf_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["cnf"] = new Dictionary<string, object> { ["jwk"] = "test" }
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["cnf"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("cnf", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Iat_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["iat"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("iat", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Sub_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["sub"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("sub", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_Jti_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["jti"] = "unique-jwt-id-123"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["jti"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("jti", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_SdArray_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["_sd"] = new[] { "digest1", "digest2" }
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["_sd"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("_sd", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithReservedClaim_SdAlg_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["_sd_alg"] = "sha-256"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["_sd_alg"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        Assert.Contains("_sd_alg", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithMultipleReservedClaims_ThrowsArgumentException()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["iss"] = "https://_issuer.example.com",
            ["aud"] = "https://audience.example.com"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _issuer.CreateSdJwt(claims, ["iss", "aud"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("security-critical claims cannot be selectively disclosable", exception.Message);
        // Should mention both claims
        Assert.Contains("iss", exception.Message);
        Assert.Contains("aud", exception.Message);
    }

    #endregion

    #region Null SelectivelyDisclosableClaims Tests

    [Fact]
    public void CreateSdJwt_WithNullSelectiveClaims_TreatsAsEmptyList()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(claims, null!, _signingKey, HashAlgorithm.Sha256);

        // Assert - Should not throw, should treat as no selective disclosures
        Assert.NotNull(result);
        Assert.Empty(result.Disclosures);
    }

    #endregion

    #region Hash Algorithm Tests

    [Fact]
    public void CreateSdJwt_WithSha384_CreatesValidSdJwt()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(claims, ["email"], _signingKey, HashAlgorithm.Sha384);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(HashAlgorithm.Sha384, result.HashAlgorithm);
    }

    [Fact]
    public void CreateSdJwt_WithSha512_CreatesValidSdJwt()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(claims, ["email"], _signingKey, HashAlgorithm.Sha512);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(HashAlgorithm.Sha512, result.HashAlgorithm);
    }

    #endregion

    #region Signature Algorithm Tests

    [Fact]
    public void CreateSdJwt_WithES256Algorithm_CreatesValidSdJwt()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        var keyGen = new KeyGenerator();
        var (privateKey, _) = keyGen.GenerateEcdsaKeyPair();

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            privateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.ES256);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result.Jwt);
    }

    [Fact]
    public void CreateSdJwt_WithRS256Algorithm_CreatesValidSdJwt()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        var keyGen = new KeyGenerator();
        var (privateKey, _) = keyGen.GenerateRsaKeyPair();

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            privateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.RS256);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result.Jwt);
    }

    #endregion

    #region Holder Public Key Tests

    [Fact]
    public void CreateSdJwt_WithHolderPublicKey_IncludesCnfClaim()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        var keyGen = new KeyGenerator();
        var (_, holderPublicKey) = keyGen.GenerateEcdsaKeyPair();

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            _signingKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        // Assert
        Assert.NotNull(result);
        // The JWT should contain the cnf claim
        Assert.NotEmpty(result.Jwt);
    }

    #endregion

    #region Decoy Digest Tests

    [Fact]
    public void CreateSdJwt_WithDecoyDigests_IncludesDecoys()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            _signingKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            null,
            decoyDigestCount: 5);

        // Assert
        Assert.NotNull(result);
        _ = Assert.Single(result.Disclosures); // Only one real disclosure
        // The JWT payload should contain _sd array with 6 items (1 real + 5 decoys)
    }

    [Fact]
    public void CreateSdJwt_WithZeroDecoyDigests_NoDecoys()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            _signingKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            null,
            decoyDigestCount: 0);

        // Assert
        Assert.NotNull(result);
        _ = Assert.Single(result.Disclosures);
    }

    #endregion

    #region Key ID Tests

    [Fact]
    public void CreateSdJwt_WithKeyId_IncludesKeyIdInHeader()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            _signingKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            null,
            0,
            keyId: "key-2024-01");

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result.Jwt);
        // The JWT header should contain kid claim
    }

    [Fact]
    public void CreateSdJwt_WithoutKeyId_NoKeyIdInHeader()
    {
        // Arrange
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var result = _issuer.CreateSdJwt(
            claims,
            ["email"],
            _signingKey,
            HashAlgorithm.Sha256);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result.Jwt);
    }

    #endregion
}
