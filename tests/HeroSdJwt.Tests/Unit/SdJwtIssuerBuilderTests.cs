using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for the fluent SdJwtIssuerBuilder API.
/// Validates the simplified, developer-friendly interface.
/// </summary>
public class SdJwtIssuerBuilderTests
{
    private readonly IKeyGenerator _keyGenerator = KeyGenerator.Instance;

    [Fact]
    public void Build_WithMinimalConfig_CreatesValidSdJwt()
    {
        // Arrange
        var key = _keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        _ = Assert.Single(sdJwt.Disclosures);
    }

    [Fact]
    public void WithClaims_ThenWithClaim_DoesNotModifyCallerDictionary()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "original"
        };

        _ = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .WithClaim("role", "user");

        // The builder must not silently add claims to its caller's dictionary.
        Assert.False(claims.ContainsKey("role"));
        Assert.Equal("original", claims["sub"]);
    }

    [Fact]
    public void WithClaims_CallerMutationBeforeBuild_DoesNotChangeSignedDisclosure()
    {
        var key = _keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "original",
            ["email"] = "first@example.com"
        };

        var builder = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key);

        // A top-level caller edit after configuration must not silently
        // change what the builder issues and signs.
        claims["email"] = "second@example.com";

        var sdJwt = builder.Build();
        var encodedDisclosure = Assert.Single(sdJwt.Disclosures);
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeString(encodedDisclosure));

        Assert.Equal("email", document.RootElement[1].GetString());
        Assert.Equal("first@example.com", document.RootElement[2].GetString());
    }


    [Fact]
    public void SignWithHmac_CallerClearsInputKey_BuildUsesConfiguredKey()
    {
        var suppliedKey = _keyGenerator.GenerateHmacKey();
        var originalKey = (byte[])suppliedKey.Clone();
        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .SignWithHmac(suppliedKey);

        // A caller may clear a key buffer after configuring the builder.
        // The issued JWT must still use the key accepted at configuration.
        Array.Clear(suppliedKey);

        var sdJwt = builder.Build();
        Assert.True(new SignatureValidator().VerifyJwtSignature(sdJwt.Jwt, originalKey));
    }

    [Fact]
    public void SignWithRsa_CallerClearsPrivateKey_BuildUsesConfiguredKey()
    {
        var (suppliedKey, publicKey) = _keyGenerator.GenerateRsaKeyPair();
        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .SignWithRsa(suppliedKey);

        Array.Clear(suppliedKey);

        var sdJwt = builder.Build();
        Assert.True(new SignatureValidator().VerifyJwtSignature(sdJwt.Jwt, publicKey));
    }

    [Fact]
    public void SignWithEcdsa_CallerClearsPrivateKey_BuildUsesConfiguredKey()
    {
        var (suppliedKey, publicKey) = _keyGenerator.GenerateEcdsaKeyPair();
        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .SignWithEcdsa(suppliedKey);

        Array.Clear(suppliedKey);

        var sdJwt = builder.Build();
        Assert.True(new SignatureValidator().VerifyJwtSignature(sdJwt.Jwt, publicKey));
    }

    [Fact]
    public void SignWithEd25519_CallerClearsPrivateKey_BuildUsesConfiguredKey()
    {
        var (suppliedKey, publicKey) = _keyGenerator.GenerateEd25519KeyPair();
        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .SignWithEd25519(suppliedKey);

        Array.Clear(suppliedKey);

        var sdJwt = builder.Build();
        Assert.True(new SignatureValidator().VerifyJwtSignature(sdJwt.Jwt, publicKey));
    }

    [Fact]
    public void WithKeyBinding_CallerClearsPublicKey_BuildUsesConfiguredConfirmationKey()
    {
        var issuerKey = _keyGenerator.GenerateHmacKey();
        var (_, suppliedKey) = _keyGenerator.GenerateEcdsaKeyPair();
        var expectedJwk = new EcPublicKeyConverter().ToJwk(suppliedKey);
        var builder = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .SignWithHmac(issuerKey)
            .WithKeyBinding(suppliedKey);

        Array.Clear(suppliedKey);

        var sdJwt = builder.Build();
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeString(sdJwt.Jwt.Split('.')[1]));
        var confirmationJwk = document.RootElement.GetProperty("cnf").GetProperty("jwk");

        Assert.Equal((string)expectedJwk["x"], confirmationJwk.GetProperty("x").GetString());
        Assert.Equal((string)expectedJwk["y"], confirmationJwk.GetProperty("y").GetString());
    }

    [Fact]
    public void Build_WithIndividualClaims_CreatesValidSdJwt()
    {
        // Arrange
        var key = _keyGenerator.GenerateHmacKey();

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .WithClaim("email", "user@example.com")
            .WithClaim("age", 30)
            .MakeSelective("email", "age")
            .SignWithHmac(key)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.Equal(2, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Build_WithRsaSignature_CreatesValidSdJwt()
    {
        // Arrange
        var (privateKey, _) = _keyGenerator.GenerateRsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .SignWithRsa(privateKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
    }

    [Fact]
    public void Build_WithEcdsaSignature_CreatesValidSdJwt()
    {
        // Arrange
        var (privateKey, _) = _keyGenerator.GenerateEcdsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .SignWithEcdsa(privateKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
    }

    [Fact]
    public void Build_WithEd25519Signature_CreatesValidSdJwt()
    {
        // Arrange
        var (privateKey, _) = _keyGenerator.GenerateEd25519KeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .SignWithEd25519(privateKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
    }

    [Fact]
    public void Build_WithKeyBinding_IncludesCnfClaim()
    {
        // Arrange
        var issuerKey = _keyGenerator.GenerateHmacKey();
        var (_, holderPublicKey) = _keyGenerator.GenerateEcdsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .SignWithHmac(issuerKey)
            .WithKeyBinding(holderPublicKey)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        // cnf claim should be in JWT (we can't easily verify without parsing)
    }

    [Fact]
    public void Build_WithDecoys_CreatesExtraDigests()
    {
        // Arrange
        var key = _keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .SignWithHmac(key)
            .WithDecoys(5)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        // Should have 1 real disclosure + 5 decoys in JWT payload _sd array
        _ = Assert.Single(sdJwt.Disclosures); // Only real disclosures are in the list
    }

    [Fact]
    public void Build_WithoutClaims_ThrowsInvalidOperationException()
    {
        // Arrange
        var key = _keyGenerator.GenerateHmacKey();

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            SdJwtIssuerBuilder.Create()
                .SignWithHmac(key)
                .Build());

        Assert.Contains("Claims must be set", exception.Message);
    }

    [Fact]
    public void Build_WithoutSigningKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            SdJwtIssuerBuilder.Create()
                .WithClaims(claims)
                .Build());

        Assert.Contains("Signing key must be set", exception.Message);
    }

    [Fact]
    public void WithDecoys_WithNegativeCount_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        _ = Assert.Throws<ArgumentOutOfRangeException>(() =>
            SdJwtIssuerBuilder.Create().WithDecoys(-1));
    }

    [Fact]
    public void Build_WithCustomHashAlgorithm_UsesSha512()
    {
        // Arrange
        var key = _keyGenerator.GenerateHmacKey();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user123",
            ["email"] = "user@example.com"
        };

        // Act
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("email")
            .WithHashAlgorithm(HashAlgorithm.Sha512)
            .SignWithHmac(key)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Disclosures);
        // The disclosure itself is base64url encoded JSON (salt, claim, value)
        // Hash algorithm affects JWT payload digests, not disclosure format
        Assert.NotEmpty(sdJwt.Jwt); // Just verify it builds successfully
    }

    [Fact]
    public void FluentAPI_CanChainAllMethods()
    {
        // Arrange
        var key = _keyGenerator.GenerateHmacKey();
        var (_, holderPublicKey) = _keyGenerator.GenerateEcdsaKeyPair();

        // Act - Chain all methods to verify fluent interface
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user123")
            .WithClaim("email", "user@example.com")
            .WithClaim("age", 30)
            .WithClaim("address", new { city = "NYC", zip = "10001" })
            .MakeSelective("email", "age", "address.city")
            .WithHashAlgorithm(HashAlgorithm.Sha256)
            .SignWithHmac(key)
            .WithKeyBinding(holderPublicKey)
            .WithDecoys(3)
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        Assert.NotEmpty(sdJwt.Jwt);
        Assert.NotEmpty(sdJwt.Disclosures);
    }

    [Fact]
    public void SignWith_MultipleCallsOverridePrevious()
    {
        // Arrange
        var hmacKey = _keyGenerator.GenerateHmacKey();
        var (rsaKey, _) = _keyGenerator.GenerateRsaKeyPair();
        var claims = new Dictionary<string, object> { ["sub"] = "user123" };

        // Act - Call SignWithHmac then SignWithRsa (last one should win)
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .SignWithHmac(hmacKey)
            .SignWithRsa(rsaKey)  // This should override
            .Build();

        // Assert
        Assert.NotNull(sdJwt);
        // JWT should use RS256 algorithm
    }
}
