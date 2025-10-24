using HeroSdJwt.Tests;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for signature algorithm support (HS256, RS256, ES256).
/// Validates that SD-JWTs can be created and verified with different signature algorithms.
/// </summary>
public class SignatureAlgorithmTests
{
    [Fact]
    public void CreateSdJwt_WithHS256_CreatesValidJwt()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var signingKey = new byte[32];
        RandomNumberGenerator.Fill(signingKey);

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256);

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);

        // Decode header to verify algorithm
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("alg", out var alg));
        Assert.Equal("HS256", alg.GetString());
    }

    [Fact]
    public void CreateSdJwt_WithRS256_CreatesValidJwt()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();

        // Generate RSA key pair (2048 bits minimum)
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-456",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            privateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.RS256);

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);

        // Decode header to verify algorithm
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("alg", out var alg));
        Assert.Equal("RS256", alg.GetString());
    }

    [Fact]
    public void CreateSdJwt_WithES256_CreatesValidJwt()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();

        // Generate ECDSA key pair (P-256 curve)
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-789",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            privateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.ES256);

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);

        // Decode header to verify algorithm
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("alg", out var alg));
        Assert.Equal("ES256", alg.GetString());
    }

    [Fact]
    public void EndToEnd_HS256_IssueAndVerify()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var signingKey = new byte[32];
        RandomNumberGenerator.Fill(signingKey);

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["name"] = "Alice",
            ["email"] = "alice@example.com"
        };

        // Act - Issue
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "name", "email" },
            signingKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256);

        // Create presentation string
        var presentation = sdJwt.ToCombinedFormat();

        // Act - Verify
        var result = verifier.VerifyPresentation(
            presentation,
            signingKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Contains("name", result.DisclosedClaims.Keys);
        Assert.Contains("email", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void EndToEnd_RS256_IssueAndVerify()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();

        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-456",
            ["name"] = "Bob",
            ["email"] = "bob@example.com"
        };

        // Act - Issue
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "name", "email" },
            privateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.RS256);

        // Create presentation string
        var presentation = sdJwt.ToCombinedFormat();

        // Act - Verify
        var result = verifier.VerifyPresentation(
            presentation,
            publicKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Contains("name", result.DisclosedClaims.Keys);
        Assert.Contains("email", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void EndToEnd_ES256_IssueAndVerify()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-789",
            ["name"] = "Charlie",
            ["email"] = "charlie@example.com"
        };

        // Act - Issue
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "name", "email" },
            privateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.ES256);

        // Create presentation string
        var presentation = sdJwt.ToCombinedFormat();

        // Act - Verify
        var result = verifier.VerifyPresentation(
            presentation,
            publicKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Contains("name", result.DisclosedClaims.Keys);
        Assert.Contains("email", result.DisclosedClaims.Keys);
    }

    [Fact]
    public void CreateSdJwt_WithRS256AndSmallKey_ThrowsArgumentException()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();

        // Generate weak RSA key (1024 bits - below minimum)
        using var rsa = RSA.Create(1024);
        var privateKey = rsa.ExportPkcs8PrivateKey();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            issuer.CreateSdJwt(
                claims,
                Array.Empty<string>(),
                privateKey,
                HashAlgorithm.Sha256,
                SignatureAlgorithm.RS256));

        Assert.Contains("2048", exception.Message);
    }

    [Fact]
    public void CreateSdJwt_WithES256AndWrongCurve_ThrowsArgumentException()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();

        // Generate ECDSA key with wrong curve (P-384 instead of P-256)
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            issuer.CreateSdJwt(
                claims,
                Array.Empty<string>(),
                privateKey,
                HashAlgorithm.Sha256,
                SignatureAlgorithm.ES256));

        Assert.Contains("P-256", exception.Message);
    }

    [Fact]
    public void VerifyPresentation_RS256WithWrongPublicKey_FailsVerification()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();

        // Issuer's key pair
        using var issuerRsa = RSA.Create(2048);
        var issuerPrivateKey = issuerRsa.ExportPkcs8PrivateKey();

        // Attacker's key pair
        using var attackerRsa = RSA.Create(2048);
        var attackerPublicKey = attackerRsa.ExportSubjectPublicKeyInfo();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["email"] = "user@example.com"
        };

        // Issue with issuer's key
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            issuerPrivateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.RS256);

        // Create presentation string
        var presentation = sdJwt.ToCombinedFormat();

        // Act - Verify with attacker's public key
        var result = verifier.TryVerifyPresentation(
            presentation,
            attackerPublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void VerifyPresentation_ES256WithWrongPublicKey_FailsVerification()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();

        // Issuer's key pair
        using var issuerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerPrivateKey = issuerEcdsa.ExportPkcs8PrivateKey();

        // Attacker's key pair
        using var attackerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attackerPublicKey = attackerEcdsa.ExportSubjectPublicKeyInfo();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["email"] = "user@example.com"
        };

        // Issue with issuer's key
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            issuerPrivateKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.ES256);

        // Create presentation string
        var presentation = sdJwt.ToCombinedFormat();

        // Act - Verify with attacker's public key
        var result = verifier.TryVerifyPresentation(
            presentation,
            attackerPublicKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void CreateSdJwt_DefaultAlgorithm_UsesHS256()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var signingKey = new byte[32];
        RandomNumberGenerator.Fill(signingKey);

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123"
        };

        // Act - Don't specify algorithm (should default to HS256)
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            signingKey,
            HashAlgorithm.Sha256);  // No signatureAlgorithm parameter

        // Assert
        var parts = sdJwt.Jwt.Split('.');
        var headerJson = Base64UrlEncoder.DecodeString(parts[0]);
        var header = JsonDocument.Parse(headerJson).RootElement;

        Assert.True(header.TryGetProperty("alg", out var alg));
        Assert.Equal("HS256", alg.GetString());
    }
}
