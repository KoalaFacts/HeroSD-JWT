using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;
using Xunit;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// Integration tests for JWT token revocation feature.
/// Tests US1 (JTI revocation) and US3 (User revocation) scenarios.
/// </summary>
public class RevocationIntegrationTests
{
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;
    private readonly KeyGenerator _keyGen = new();

    // ═══════════════════════════════════════════════════════════════════════
    // US1: JTI Revocation Tests (Individual Token Blacklisting)
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task US1_UserLogout_RevokesSpecificToken()
    {
        // Arrange: Create issuer and verifier with revocation enabled
        var key = _keyGen.GenerateHmacKey();
        var revocationStore = new InMemoryRevocationStore();
        var options = new SdJwtVerificationOptions();
        var verifier = TestHelpers.CreateVerifierWithRevocation(options, revocationStore);

        // Act 1: Issue a token with JTI
        var jti = Guid.NewGuid().ToString();
        var token = SdJwtBuilder.Create()
            .WithClaim("sub", "alice@example.com")
            .WithClaim("jti", jti)
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        // Assert 1: Token is valid before revocation
        var result1 = verifier.TryVerifyPresentation(token.ToPresentation(), key);
        Assert.True(result1.IsValid, "Token should be valid before revocation");

        // Act 2: User logs out - revoke the token by JTI
        var exp = DateTimeOffset.UtcNow.AddHours(1);
        await revocationStore.RevokeJtiAsync(jti, exp, _ct);

        // Assert 2: Token is now revoked
        var result2 = verifier.TryVerifyPresentation(token.ToPresentation(), key);
        Assert.False(result2.IsValid, "Token should be revoked after logout");
        Assert.Contains(ErrorCode.TokenRevoked, result2.Errors);
    }

    [Fact]
    public async Task US1_RevokedToken_ThrowsTokenRevokedException()
    {
        // Arrange
        var key = _keyGen.GenerateHmacKey();
        var revocationStore = new InMemoryRevocationStore();
        var options = new SdJwtVerificationOptions();
        var verifier = TestHelpers.CreateVerifierWithRevocation(options, revocationStore);

        var jti = "revoked-token-123";
        var token = SdJwtBuilder.Create()
            .WithClaim("jti", jti)
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        // Act: Revoke token then verify with throwing API
        await revocationStore.RevokeJtiAsync(jti, DateTimeOffset.UtcNow.AddHours(1), _ct);

        // Assert: Throws TokenRevokedException
        var ex = Assert.Throws<TokenRevokedException>(() =>
            verifier.VerifyPresentation(token.ToPresentation(), key));

        Assert.Equal(jti, ex.Jti);
        Assert.Equal(RevocationReason.JtiRevoked, ex.Reason);
        Assert.Equal(ErrorCode.TokenRevoked, ex.ErrorCode);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // US2: Key ID Revocation Tests (Compromised Key Scenario)
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task US2_CompromisedKey_RevokesAllTokensFromKey()
    {
        // Arrange
        var key = _keyGen.GenerateHmacKey();
        var revocationStore = new InMemoryRevocationStore();
        var options = new SdJwtVerificationOptions();
        var verifier = TestHelpers.CreateVerifierWithRevocation(options, revocationStore);

        // Act 1: Issue multiple tokens with same kid
        var kid = "key-2024-10";
        var token1 = SdJwtBuilder.Create()
            .WithKeyId(kid)
            .WithClaim("sub", "alice@example.com")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        var token2 = SdJwtBuilder.Create()
            .WithKeyId(kid)
            .WithClaim("sub", "bob@example.com")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        // Assert 1: Both tokens are valid before key revocation
        Assert.True(verifier.TryVerifyPresentation(token1.ToPresentation(), key).IsValid);
        Assert.True(verifier.TryVerifyPresentation(token2.ToPresentation(), key).IsValid);

        // Act 2: Revoke the signing key
        await revocationStore.RevokeKeyAsync(kid, _ct);

        // Assert 2: All tokens from that key are now revoked
        var result1 = verifier.TryVerifyPresentation(token1.ToPresentation(), key);
        var result2 = verifier.TryVerifyPresentation(token2.ToPresentation(), key);

        Assert.False(result1.IsValid);
        Assert.False(result2.IsValid);
        Assert.Contains(ErrorCode.TokenRevokedByKey, result1.Errors);
        Assert.Contains(ErrorCode.TokenRevokedByKey, result2.Errors);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // US3: User ID Revocation Tests (Emergency Lockdown / Logout Everywhere)
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task US3_UserRevocation_InvalidatesAllUserTokens()
    {
        // Arrange
        var key = _keyGen.GenerateHmacKey();
        var revocationStore = new InMemoryRevocationStore();
        var options = new SdJwtVerificationOptions();
        var verifier = TestHelpers.CreateVerifierWithRevocation(options, revocationStore);

        // Act 1: Issue multiple tokens for the same user (different devices)
        var userId = "alice@example.com";
        var tokenDevice1 = SdJwtBuilder.Create()
            .WithClaim("sub", userId)
            .WithClaim("jti", "token-device-1")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        var tokenDevice2 = SdJwtBuilder.Create()
            .WithClaim("sub", userId)
            .WithClaim("jti", "token-device-2")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        // Assert 1: Both tokens are valid before user revocation
        Assert.True(verifier.TryVerifyPresentation(tokenDevice1.ToPresentation(), key).IsValid);
        Assert.True(verifier.TryVerifyPresentation(tokenDevice2.ToPresentation(), key).IsValid);

        // Act 2: Revoke all tokens for the user (emergency lockdown)
        await revocationStore.RevokeUserAsync(userId, _ct);

        // Assert 2: All tokens for that user are now revoked
        var result1 = verifier.TryVerifyPresentation(tokenDevice1.ToPresentation(), key);
        var result2 = verifier.TryVerifyPresentation(tokenDevice2.ToPresentation(), key);

        Assert.False(result1.IsValid);
        Assert.False(result2.IsValid);
        Assert.Contains(ErrorCode.TokenRevokedByUser, result1.Errors);
        Assert.Contains(ErrorCode.TokenRevokedByUser, result2.Errors);
    }

    [Fact]
    public async Task US3_UserUnrevocation_AllowsNewTokens()
    {
        // Arrange
        var key = _keyGen.GenerateHmacKey();
        var revocationStore = new InMemoryRevocationStore();
        var options = new SdJwtVerificationOptions();
        var verifier = TestHelpers.CreateVerifierWithRevocation(options, revocationStore);

        var userId = "charlie@example.com";

        // Act 1: Revoke user
        await revocationStore.RevokeUserAsync(userId, _ct);

        // Assert 1: Token fails verification
        var revokedToken = SdJwtBuilder.Create()
            .WithClaim("sub", userId)
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        Assert.False(verifier.TryVerifyPresentation(revokedToken.ToPresentation(), key).IsValid);

        // Act 2: Un-revoke user (incident resolved)
        await revocationStore.UnrevokeUserAsync(userId, _ct);

        // Assert 2: New token is now valid
        var newToken = SdJwtBuilder.Create()
            .WithClaim("sub", userId)
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        var result = verifier.TryVerifyPresentation(newToken.ToPresentation(), key);
        Assert.True(result.IsValid);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // No Revocation Store Test
    // ═══════════════════════════════════════════════════════════════════════

    [Fact]
    public void NoRevocationStore_TokenWorksNormally()
    {
        // Arrange: No revocation store provided - revocation checks are skipped
        var key = _keyGen.GenerateHmacKey();
        var options = new SdJwtVerificationOptions();
        var verifier = TestHelpers.CreateVerifierWithRevocation(options, revocationStore: null);

        // Act: Issue token
        var token = SdJwtBuilder.Create()
            .WithClaim("jti", "test-jti")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .SignWithHmac(key)
            .Build();

        // Assert: Token works normally (revocation checks are skipped when no store)
        var result = verifier.TryVerifyPresentation(token.ToPresentation(), key);
        Assert.True(result.IsValid);
    }
}
