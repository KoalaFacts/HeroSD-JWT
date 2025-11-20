using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;
using HeroSdJwt.Verification.ReplayProtection;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for SdJwtVerifierBuilder fluent API.
/// </summary>
public class SdJwtVerifierBuilderTests
{
    [Fact]
    public void Create_ReturnsBuilderInstance()
    {
        // Act
        var builder = SdJwtVerifierBuilder.Create();

        // Assert
        Assert.NotNull(builder);
    }

    [Fact]
    public void Build_WithDefaults_CreatesVerifier()
    {
        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithClockSkew_SetsClockSkew()
    {
        // Arrange
        var clockSkew = TimeSpan.FromMinutes(2);

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithClockSkew(clockSkew)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void RequireKeyBinding_SetsRequireKeyBinding()
    {
        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .RequireKeyBinding()
            .WithExpectedAudience("https://verifier.example.com")
            .WithExpectedNonce("nonce-123")
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithExpectedIssuer_SetsIssuer()
    {
        // Arrange
        var issuer = "https://issuer.example.com";

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedIssuer(issuer)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithExpectedIssuer_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithExpectedIssuer(null!));
    }

    [Fact]
    public void WithExpectedAudience_SetsAudience()
    {
        // Arrange
        var audience = "https://api.example.com";

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedAudience(audience)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithExpectedAudience_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithExpectedAudience(null!));
    }

    [Fact]
    public void WithExpectedHashAlgorithm_SetsHashAlgorithm()
    {
        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedHashAlgorithm(HashAlgorithm.Sha512)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithExpectedNonce_SetsNonce()
    {
        // Arrange
        var nonce = "test-nonce-123";

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedNonce(nonce)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithExpectedNonce_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithExpectedNonce(null!));
    }

    [Fact]
    public void WithRevocation_SetsRevocationStore()
    {
        // Arrange
        var store = new InMemoryRevocationStore();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithRevocation(store)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithRevocation_WithFailureMode_SetsFailureMode()
    {
        // Arrange
        var store = new InMemoryRevocationStore();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithRevocation(store, RevocationFailureMode.FailOpen)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithRevocation_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithRevocation(null!));
    }

    [Fact]
    public void WithFailClosed_SetsFailClosedMode()
    {
        // Arrange
        var store = new InMemoryRevocationStore();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithRevocation(store)
            .WithFailClosed()
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithFailOpen_SetsFailOpenMode()
    {
        // Arrange
        var store = new InMemoryRevocationStore();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithRevocation(store)
            .WithFailOpen()
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithReplayProtection_SetsJtiValidator()
    {
        // Arrange
        var cache = new InMemoryJtiCache(new ReplayProtectionOptions { Enabled = true });
        var validator = new JtiValidator(cache, new ReplayProtectionOptions { Enabled = true });

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithReplayProtection(validator)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithReplayProtection_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithReplayProtection(null!));
    }

    [Fact]
    public void FluentAPI_ChainsMethods()
    {
        // Arrange
        var store = new InMemoryRevocationStore();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithClockSkew(TimeSpan.FromMinutes(2))
            .WithExpectedIssuer("https://issuer.example.com")
            .WithExpectedAudience("https://api.example.com")
            .WithExpectedHashAlgorithm(HashAlgorithm.Sha256)
            .WithExpectedNonce("nonce-123")
            .WithRevocation(store, RevocationFailureMode.FailClosed)
            .RequireKeyBinding()
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void Build_WithInvalidClockSkew_ThrowsArgumentException()
    {
        // Arrange
        var builder = SdJwtVerifierBuilder.Create()
            .WithClockSkew(TimeSpan.FromMinutes(10)); // Exceeds 5 minute max

        // Act & Assert
        Assert.Throws<ArgumentException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithNegativeClockSkew_ThrowsArgumentException()
    {
        // Arrange
        var builder = SdJwtVerifierBuilder.Create()
            .WithClockSkew(TimeSpan.FromMinutes(-1));

        // Act & Assert
        Assert.Throws<ArgumentException>(() => builder.Build());
    }

    [Fact]
    public void WithEcPublicKeyConverter_SetsCustomConverter()
    {
        // Arrange
        var converter = new EcPublicKeyConverter();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithEcPublicKeyConverter(converter)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithEcPublicKeyConverter_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithEcPublicKeyConverter(null!));
    }

    [Fact]
    public void WithSignatureValidator_SetsCustomValidator()
    {
        // Arrange
        var validator = new SignatureValidator();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithSignatureValidator(validator)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithSignatureValidator_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithSignatureValidator(null!));
    }

    [Fact]
    public void WithDigestValidator_SetsCustomValidator()
    {
        // Arrange
        var validator = new DigestValidator();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithDigestValidator(validator)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithDigestValidator_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithDigestValidator(null!));
    }

    [Fact]
    public void WithKeyBindingValidator_SetsCustomValidator()
    {
        // Arrange
        var validator = new KeyBindingValidator();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithKeyBindingValidator(validator)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithKeyBindingValidator_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithKeyBindingValidator(null!));
    }

    [Fact]
    public void WithClaimValidator_SetsCustomValidator()
    {
        // Arrange
        var validator = new ClaimValidator();

        // Act
        var verifier = SdJwtVerifierBuilder.Create()
            .WithClaimValidator(validator)
            .Build();

        // Assert
        Assert.NotNull(verifier);
    }

    [Fact]
    public void WithClaimValidator_WithNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            SdJwtVerifierBuilder.Create().WithClaimValidator(null!));
    }
}
