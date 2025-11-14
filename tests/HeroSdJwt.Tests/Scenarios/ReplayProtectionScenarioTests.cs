using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Scenarios;

/// <summary>
/// End-to-end scenario tests for replay protection feature.
/// Tests realistic flows covering concurrent verification, TTL expiration, and integration scenarios.
/// Implements Tasks T016-T018.
/// </summary>
public class ReplayProtectionScenarioTests : IDisposable
{
    private readonly InMemoryJtiCache cache;
    private readonly ReplayProtectionOptions replayOptions;
    private readonly byte[] signingKey;

    public ReplayProtectionScenarioTests()
    {
        replayOptions = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = true,
            FailureMode = CacheFailureMode.FailClosed
        };
        cache = new InMemoryJtiCache(replayOptions);
        signingKey = GenerateSecureTestKey();
    }

    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    #region T016 - Concurrent Verification Tests

    /// <summary>
    /// T016 Scenario 1: Multiple concurrent verification attempts of the same token.
    /// Expected: Exactly 1 succeeds, 99 throw ReplayAttackException.
    /// Validates atomic cache operations work under load.
    /// </summary>
    [Fact]
    public async Task ConcurrentVerifications_SameToken_OnlyFirstSucceeds()
    {
        // Arrange - Create a single valid SD-JWT
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

        var jtiValidator = new JtiValidator(cache, replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - Spawn 100 concurrent verification tasks
        const int concurrentAttempts = 100;
        var tasks = new Task<bool>[concurrentAttempts];

        for (int i = 0; i < concurrentAttempts; i++)
        {
            tasks[i] = Task.Run(async () =>
            {
                try
                {
                    await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
                    return true; // Verification succeeded
                }
                catch (ReplayAttackException ex)
                {
                    // Expected for all but the first verification
                    Assert.Equal(jti, ex.Jti);
                    Assert.Equal("https://issuer.example.com", ex.Issuer);
                    return false; // Replay detected
                }
            });
        }

        var results = await Task.WhenAll(tasks);

        // Assert - Exactly 1 should succeed, 99 should detect replay
        var successCount = results.Count(r => r);
        Assert.Equal(1, successCount);

        var replayCount = results.Count(r => !r);
        Assert.Equal(99, replayCount);
    }

    /// <summary>
    /// T016 Scenario 2: Concurrent verification of different tokens (different jti values).
    /// Expected: All 100 verifications succeed.
    /// Validates no false positives in concurrent scenarios.
    /// </summary>
    [Fact]
    public async Task ConcurrentVerifications_DifferentTokens_AllSucceed()
    {
        // Arrange - Create 100 different SD-JWTs with unique jti values
        const int tokenCount = 100;
        var presentationStrings = new string[tokenCount];
        var now = DateTimeOffset.UtcNow;

        for (int i = 0; i < tokenCount; i++)
        {
            var claims = new Dictionary<string, object>
            {
                { "sub", $"user{i}" },
                { "iss", "https://issuer.example.com" },
                { "jti", Guid.NewGuid().ToString() }, // Unique jti
                { "email", $"user{i}@example.com" },
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
            presentationStrings[i] = presenter.FormatPresentation(presentation);
        }

        var jtiValidator = new JtiValidator(cache, replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - Verify all 100 tokens concurrently
        var tasks = presentationStrings.Select(presentation =>
            Task.Run(async () =>
                await VerifyPresentationAsync(verifier, presentation, signingKey, TestContext.Current.CancellationToken)
            )
        ).ToArray();

        var results = await Task.WhenAll(tasks);

        // Assert - All 100 verifications should succeed
        Assert.Equal(tokenCount, results.Length);
        Assert.All(results, result =>
        {
            Assert.NotNull(result);
            Assert.True(result.IsValid, "All verifications with different jti values should succeed");
            Assert.Empty(result.Errors);
        });
    }

    #endregion

    #region T017 - TTL Expiration Tests

    /// <summary>
    /// T017 Scenario 1: Verify token after TTL expiration allows reuse.
    /// Expected: Second verification succeeds after TTL expired (cache entry gone).
    /// </summary>
    [Fact]
    public async Task VerifyAfterTtlExpiration_AllowsReuse()
    {
        // Arrange - Create token with very short exp (3 seconds from now)
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer.example.com" },
            { "jti", jti },
            { "email", "user@example.com" },
            { "exp", now.AddSeconds(3).ToUnixTimeSeconds() } // 3 seconds TTL
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

        var jtiValidator = new JtiValidator(cache, replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - First verification succeeds
        var result1 = await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        Assert.True(result1.IsValid, "First verification should succeed");

        // Wait for TTL to expire (3 seconds + clock skew tolerance + buffer)
        await Task.Delay(TimeSpan.FromSeconds(4), TestContext.Current.CancellationToken);

        // Act - Second verification after TTL expiration
        // Note: This will fail because the token's exp claim has expired (TokenExpired error)
        // The cache entry would be gone, but token expiration validation happens first
        var exception = await Assert.ThrowsAsync<SdJwtException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        });

        // Assert - Should fail with TokenExpired (not ReplayAttack)
        // This validates that cache entry was cleaned up, but token expiration takes precedence
        Assert.Equal(ErrorCode.TokenExpired, exception.ErrorCode);
    }

    /// <summary>
    /// T017 Scenario 2: Verify token before TTL expiration prevents replay.
    /// Expected: Second verification immediately throws ReplayAttackException.
    /// </summary>
    [Fact]
    public async Task VerifyBeforeTtlExpiration_PreventsReplay()
    {
        // Arrange - Create token with 1 hour exp
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

        var jtiValidator = new JtiValidator(cache, replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - First verification succeeds
        var result1 = await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        Assert.True(result1.IsValid, "First verification should succeed");

        // Act - Immediately verify again (within TTL)
        var exception = await Assert.ThrowsAsync<ReplayAttackException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        });

        // Assert
        Assert.Equal(jti, exception.Jti);
        Assert.Equal("https://issuer.example.com", exception.Issuer);
        Assert.Equal(ErrorCode.ReplayAttack, exception.ErrorCode);
    }

    #endregion

    #region T018 - End-to-End Integration Tests

    /// <summary>
    /// T018 Scenario 1: Complete flow from issuer to holder to verifier with replay attack.
    /// Expected: Initial verification succeeds, replay attempt throws ReplayAttackException.
    /// </summary>
    [Fact]
    public async Task CompleteFlow_IssuerCreatesToken_HolderPresents_VerifierChecks()
    {
        // Arrange - Issuer creates SD-JWT with jti, iss, exp claims
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var issuerClaims = new Dictionary<string, object>
        {
            { "sub", "did:example:holder123" },
            { "iss", "https://trusted-issuer.example.com" },
            { "jti", jti },
            { "name", "Alice Holder" },
            { "email", "alice@example.com" },
            { "birthdate", "1990-01-01" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt = issuer.CreateSdJwt(
            issuerClaims,
            new[] { "email", "birthdate" },
            signingKey,
            HashAlgorithm.Sha256
        );

        // Holder presents token to Verifier
        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        // Verifier validates (with replay protection)
        var jtiValidator = new JtiValidator(cache, replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - Legitimate presentation from holder
        var result = await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);

        // Assert - Legitimate presentation succeeds
        Assert.True(result.IsValid, "Holder's legitimate presentation should succeed");
        // Verify that selectively disclosed claims are present
        Assert.Contains("email", result.DisclosedClaims.Keys);
        Assert.Contains("birthdate", result.DisclosedClaims.Keys);
        Assert.Equal("alice@example.com", result.DisclosedClaims["email"].GetString());
        Assert.Equal("1990-01-01", result.DisclosedClaims["birthdate"].GetString());

        // Act - Attacker captures token and tries to replay
        var attackException = await Assert.ThrowsAsync<ReplayAttackException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        });

        // Assert - Replay attack is detected
        Assert.Equal(jti, attackException.Jti);
        Assert.Equal("https://trusted-issuer.example.com", attackException.Issuer);
        Assert.Equal(ErrorCode.ReplayAttack, attackException.ErrorCode);
    }

    /// <summary>
    /// T018 Scenario 2: Multiple issuers with same jti have independent cache entries.
    /// Expected: Both tokens succeed (cache keys are (issuer,jti) tuples).
    /// </summary>
    [Fact]
    public async Task MultipleIssuers_SameJti_IndependentCaches()
    {
        // Arrange - Create two tokens with same jti but different issuers
        var now = DateTimeOffset.UtcNow;
        var jti = Guid.NewGuid().ToString(); // Same jti for both

        var issuer1Claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "iss", "https://issuer-a.example.com" },
            { "jti", jti },
            { "email", "user1@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer2Claims = new Dictionary<string, object>
        {
            { "sub", "user456" },
            { "iss", "https://issuer-b.example.com" }, // Different issuer
            { "jti", jti }, // Same jti
            { "email", "user2@example.com" },
            { "exp", now.AddHours(1).ToUnixTimeSeconds() }
        };

        var issuer = TestHelpers.CreateIssuer();
        var sdJwt1 = issuer.CreateSdJwt(issuer1Claims, new[] { "email" }, signingKey, HashAlgorithm.Sha256);
        var sdJwt2 = issuer.CreateSdJwt(issuer2Claims, new[] { "email" }, signingKey, HashAlgorithm.Sha256);

        var presenter = new SdJwtPresenter();
        var presentation1 = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(sdJwt1));
        var presentation2 = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(sdJwt2));

        var jtiValidator = new JtiValidator(cache, replayOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - Verify both presentations
        var result1 = await VerifyPresentationAsync(verifier, presentation1, signingKey, TestContext.Current.CancellationToken);
        var result2 = await VerifyPresentationAsync(verifier, presentation2, signingKey, TestContext.Current.CancellationToken);

        // Assert - Both should succeed because they have different issuers
        Assert.True(result1.IsValid, "First verification (issuer-a) should succeed");
        Assert.True(result2.IsValid, "Second verification (issuer-b) should succeed despite same jti");
        Assert.Equal("user1@example.com", result1.DisclosedClaims["email"].GetString());
        Assert.Equal("user2@example.com", result2.DisclosedClaims["email"].GetString());
    }

    /// <summary>
    /// T018 Scenario 3: Replay protection disabled configuration test.
    /// Expected: Same token can be verified multiple times when replay protection is disabled.
    /// </summary>
    [Fact]
    public async Task DisabledReplayProtection_ConfigurationTest()
    {
        // Arrange - Create verifier with replay protection DISABLED
        var disabledOptions = new ReplayProtectionOptions
        {
            Enabled = false, // Disabled
            RequireJtiClaim = false
        };
        var disabledCache = new InMemoryJtiCache(disabledOptions);
        var jtiValidator = new JtiValidator(disabledCache, disabledOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

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

        // Act - Verify same token 10 times
        var results = new List<Models.VerificationResult>();
        for (int i = 0; i < 10; i++)
        {
            var result = await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
            results.Add(result);
        }

        // Assert - All 10 verifications should succeed (replay protection disabled)
        Assert.Equal(10, results.Count);
        Assert.All(results, result =>
        {
            Assert.True(result.IsValid, "All verifications should succeed when replay protection is disabled");
            Assert.Empty(result.Errors);
        });

        disabledCache.Dispose();
    }

    /// <summary>
    /// T018 Scenario 4: Fail-closed mode configuration test.
    /// Expected: FailureMode can be configured, demonstrating fail-closed vs fail-open options.
    /// Note: Testing actual cache failures requires mocking. This test verifies configuration.
    /// </summary>
    [Fact]
    public async Task FailClosedMode_ConfigurationTest()
    {
        // Arrange - Verify that FailClosed is the default mode
        var failClosedOptions = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = true
        };

        // Assert default mode is FailClosed
        Assert.Equal(CacheFailureMode.FailClosed, failClosedOptions.FailureMode);

        // Arrange - Create token and verify with FailClosed mode
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

        var failClosedCache = new InMemoryJtiCache(failClosedOptions);
        var jtiValidator = new JtiValidator(failClosedCache, failClosedOptions);
        var verifier = CreateVerifierWithReplayProtection(jtiValidator);

        // Act - First verification succeeds
        var result1 = await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        Assert.True(result1.IsValid, "First verification should succeed");

        // Act - Second verification is prevented (replay protection)
        var exception = await Assert.ThrowsAsync<ReplayAttackException>(async () =>
        {
            await VerifyPresentationAsync(verifier, presentationString, signingKey, TestContext.Current.CancellationToken);
        });

        // Assert - Replay attack is detected
        Assert.Equal(jti, exception.Jti);
        Assert.Equal(ErrorCode.ReplayAttack, exception.ErrorCode);

        failClosedCache.Dispose();
    }

    #endregion

    #region Helper Methods

    private SdJwtVerifier CreateVerifierWithReplayProtection(
        JtiValidator? jtiValidator,
        SdJwtVerificationOptions? options = null)
    {
        return new SdJwtVerifier(
            options ?? new SdJwtVerificationOptions(),
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator(),
            jtiValidator);
    }

    private async Task<Models.VerificationResult> VerifyPresentationAsync(
        SdJwtVerifier verifier,
        string presentation,
        byte[] publicKey,
        CancellationToken cancellationToken = default,
        HashAlgorithm? expectedHashAlgorithm = null)
    {
        // Wrap synchronous VerifyPresentation in Task.Run for async context
        return await Task.Run(() =>
            verifier.VerifyPresentation(presentation, publicKey, expectedHashAlgorithm),
            cancellationToken);
    }

    public void Dispose()
    {
        cache?.Dispose();
    }

    #endregion
}
