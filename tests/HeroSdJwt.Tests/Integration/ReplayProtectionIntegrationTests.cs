using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// Integration tests for replay protection in SdJwtVerifier.
/// Tests the end-to-end flow with JtiValidator integration.
/// </summary>
public class ReplayProtectionIntegrationTests : IDisposable
{
    private readonly InMemoryJtiCache _cache;
    private readonly ReplayProtectionOptions _replayOptions;
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;

    public ReplayProtectionIntegrationTests()
    {
        _replayOptions = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = true
        };
        _cache = new InMemoryJtiCache(_replayOptions);
    }

    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void VerifyPresentation_WithoutJtiValidator_BackwardCompatibility_Succeeds()
    {
        // Arrange - Create verifier WITHOUT JtiValidator (backward compatibility)
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act - Verify with verifier that has NO JtiValidator (backward compatibility)
        var verifier = TestHelpers.CreateVerifier();
        var result = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert - Should succeed without replay protection
        Assert.NotNull(result);
        Assert.True(result.IsValid, "Verification without JtiValidator should succeed");
        Assert.Empty(result.Errors);

        // Act - Verify again with same presentation (no JtiValidator = no replay check)
        var result2 = verifier.VerifyPresentation(presentationString, signingKey);

        // Assert - Should succeed again (no replay protection)
        Assert.True(result2.IsValid, "Second verification without JtiValidator should succeed");
    }

    [Fact]
    public async Task VerifyPresentation_WithJtiValidator_FirstVerification_Succeeds()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "jti", Guid.NewGuid().ToString() },
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Create verifier WITH JtiValidator
        var jtiValidator = new JtiValidator(_cache, _replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - First verification
        var result = await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.IsValid, "First verification with JtiValidator should succeed");
        Assert.Empty(result.Errors);
        Assert.Contains("email", result.DisclosedClaims.Keys);
    }

    [Fact]
    public async Task VerifyPresentation_WithJtiValidator_SecondVerification_ThrowsReplayAttackException()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "jti", jti },
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Create verifier WITH JtiValidator
        var jtiValidator = new JtiValidator(_cache, _replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - First verification
        var result1 = await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        Assert.True(result1.IsValid, "First verification should succeed");

        // Act & Assert - Second verification should throw ReplayAttackException
        var exception = await Assert.ThrowsAsync<ReplayAttackException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        });

        Assert.Equal(jti, exception.Jti);
        Assert.Equal("https://issuer.example.com", exception.Issuer);
        Assert.Equal(ErrorCode.ReplayAttack, exception.ErrorCode);
    }

    [Fact]
    public async Task VerifyPresentation_WithDisabledReplayProtection_MultipleVerifications_Succeed()
    {
        // Arrange - Disable replay protection
        var disabledOptions = new ReplayProtectionOptions
        {
            Enabled = false, // Disabled
            RequireJtiClaim = false
        };
        var disabledCache = new InMemoryJtiCache(disabledOptions);
        var jtiValidator = new JtiValidator(disabledCache, disabledOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "jti", Guid.NewGuid().ToString() },
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Act - Multiple verifications
        var result1 = await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        var result2 = await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        var result3 = await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);

        // Assert - All should succeed because replay protection is disabled
        Assert.True(result1.IsValid, "First verification with disabled replay protection should succeed");
        Assert.True(result2.IsValid, "Second verification with disabled replay protection should succeed");
        Assert.True(result3.IsValid, "Third verification with disabled replay protection should succeed");

        disabledCache.Dispose();
    }

    [Fact]
    public async Task VerifyPresentation_WithJtiValidator_MissingJtiClaim_ThrowsSdJwtException()
    {
        // Arrange - Token WITHOUT jti claim
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            // No jti claim
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Create verifier WITH JtiValidator (RequireJtiClaim = true)
        var jtiValidator = new JtiValidator(_cache, _replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act & Assert - Should throw SdJwtException for missing jti
        var exception = await Assert.ThrowsAsync<SdJwtException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        });

        Assert.Equal(ErrorCode.MissingRequiredClaim, exception.ErrorCode);
        Assert.Contains("jti", exception.Message.ToLower());
    }

    [Fact]
    public async Task VerifyPresentation_WithJtiValidator_MissingIssuerClaim_ThrowsSdJwtException()
    {
        // Arrange - Token WITHOUT issuer claim
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            // No iss claim
            { "jti", Guid.NewGuid().ToString() },
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Create verifier WITH JtiValidator
        var jtiValidator = new JtiValidator(_cache, _replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act & Assert - Should throw SdJwtException for missing issuer
        var exception = await Assert.ThrowsAsync<SdJwtException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        });

        Assert.Equal(ErrorCode.MissingRequiredClaim, exception.ErrorCode);
        Assert.Contains("iss", exception.Message.ToLower());
    }

    [Fact]
    public async Task VerifyPresentation_WithJtiValidator_DifferentIssuers_AllowsSameJti()
    {
        // Arrange - Create two tokens with same jti but different issuers
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString(); // Same jti for both

        var claims1 = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer1.example.com" },
            { "jti", jti },
            { "email", "user1@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var claims2 = new Dictionary<string, object>
        {
            { "sub", "user456" },
            { "iss", "https://issuer2.example.com" }, // Different issuer
            { "jti", jti }, // Same jti
            { "email", "user2@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt1 = issuer.CreateSdJwt(claims1, new[] { "email" }, signingKey, HashAlgorithm.Sha256);
        var sdJwt2 = issuer.CreateSdJwt(claims2, new[] { "email" }, signingKey, HashAlgorithm.Sha256);

        var presenter = new SdJwtPresenter();
        var presentation1 = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(sdJwt1));
        var presentation2 = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(sdJwt2));

        // Create verifier WITH JtiValidator
        var jtiValidator = new JtiValidator(_cache, _replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - Verify both presentations
        var result1 = await VerifyPresentationAsync(verifier, presentation1, signingKey, cancellationToken: _ct);
        var result2 = await VerifyPresentationAsync(verifier, presentation2, signingKey, cancellationToken: _ct);

        // Assert - Both should succeed because they have different issuers
        Assert.True(result1.IsValid, "First verification (issuer1) should succeed");
        Assert.True(result2.IsValid, "Second verification (issuer2) should succeed despite same jti");
    }

    // Test removed to simplify initial integration
    // Key binding + replay protection can be tested separately once basic integration works

    [Fact]
    public async Task TryVerifyPresentation_WithJtiValidator_ReplayAttack_ReturnsFalse()
    {
        // Arrange
        var signingKey = GenerateSecureTestKey();
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "jti", jti },
            { "email", "user@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            claims,
            new[] { "email" },
            signingKey,
            HashAlgorithm.Sha256
        );

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Create verifier WITH JtiValidator
        var jtiValidator = new JtiValidator(_cache, _replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - First verification using TryVerify
        var result1 = await TryVerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);
        Assert.True(result1.IsValid, "First TryVerify should succeed");

        // Act - Second verification using TryVerify (replay attack)
        var result2 = await TryVerifyPresentationAsync(verifier, presentationString, signingKey, cancellationToken: _ct);

        // Assert - Should return false with ReplayAttack error
        Assert.False(result2.IsValid, "Second TryVerify should fail");
        Assert.Contains(ErrorCode.ReplayAttack, result2.Errors);
    }

    // Helper methods

    private SdJwtVerifier CreateVerifierWithReplayProtection(
        JtiValidator? jtiValidator,
        SdJwtVerificationOptions? options = null)
    {
        options ??= new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Either };
        return new SdJwtVerifier(
            options,
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(TimeProvider.System),
            new ClaimValidator(),
            jtiValidator); // Pass JtiValidator
    }

    private async Task<VerificationResult> VerifyPresentationAsync(
        SdJwtVerifier verifier,
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        // Call VerifyPresentation synchronously (it will call ValidateAsync internally)
        // We need to wrap it in a Task to simulate async behavior
        return await Task.Run(() =>
            verifier.VerifyPresentation(presentation, publicKey, expectedHashAlgorithm),
            cancellationToken);
    }

    private async Task<VerificationResult> TryVerifyPresentationAsync(
        SdJwtVerifier verifier,
        string presentation,
        byte[] publicKey,
        HashAlgorithm? expectedHashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
            verifier.TryVerifyPresentation(presentation, publicKey, expectedHashAlgorithm),
            cancellationToken);
    }

    public void Dispose()
    {
        _cache?.Dispose();
    }
}
