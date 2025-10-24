using HeroSdJwt.Cryptography;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using HeroSdJwt.Primitives;
using HeroSdJwt.Exceptions;
using Xunit;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// Integration tests for complete JWT key rotation lifecycle scenarios.
/// Tests US3: Manage Key Rotation Lifecycle - validates end-to-end workflows
/// including overlap periods, key removal, emergency revocation, and sequential rotation.
/// </summary>
public class KeyRotationEndToEndTests
{
    private readonly KeyGenerator keyGen = new();

    [Fact]
    public void KeyRotation_OverlapPeriod_BothKeysVerify()
    {
        // Arrange - Simulate Day 1-30 of key rotation with overlap period
        var keyV1 = keyGen.GenerateHmacKey();
        var keyV2 = keyGen.GenerateHmacKey();

        // Day 1: Only key-v1 exists
        var issuer = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("email", "alice@example.com")
            .MakeSelective("email")
            .WithKeyId("key-v1")
            .SignWithHmac(keyV1);

        var tokenWithV1 = issuer.Build();

        // Day 15: Add key-v2 (overlap period begins)
        // Day 20: Start issuing tokens with key-v2
        var issuerV2 = SdJwtBuilder.Create()
            .WithClaim("sub", "user-456")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("role", "admin")
            .MakeSelective("role")
            .WithKeyId("key-v2")
            .SignWithHmac(keyV2);

        var tokenWithV2 = issuerV2.Build();

        // Key resolver with both keys (overlap period)
        var keys = new Dictionary<string, byte[]>
        {
            ["key-v1"] = keyV1,
            ["key-v2"] = keyV2
        };
        KeyResolver resolver = kid => keys.GetValueOrDefault(kid);

        // Act - Verify both tokens work during overlap
        var verifier = new SdJwtVerifier();
        var resultV1 = verifier.TryVerifyPresentation(tokenWithV1.ToPresentation("email"), resolver);
        var resultV2 = verifier.TryVerifyPresentation(tokenWithV2.ToPresentation("role"), resolver);

        // Assert - Both keys work during overlap period
        Assert.True(resultV1.IsValid, $"key-v1 verification failed: {string.Join(", ", resultV1.Errors)}");
        Assert.Equal("alice@example.com", resultV1.DisclosedClaims["email"].GetString());

        Assert.True(resultV2.IsValid, $"key-v2 verification failed: {string.Join(", ", resultV2.Errors)}");
        Assert.Equal("admin", resultV2.DisclosedClaims["role"].GetString());
    }

    [Fact]
    public void KeyRotation_RemoveOldKey_OnlyNewKeyVerifies()
    {
        // Arrange - Simulate Day 30+ where old key is removed
        var keyV1 = keyGen.GenerateHmacKey();
        var keyV2 = keyGen.GenerateHmacKey();

        // Create tokens with both keys
        var tokenWithV1 = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v1")
            .SignWithHmac(keyV1)
            .Build();

        var tokenWithV2 = SdJwtBuilder.Create()
            .WithClaim("sub", "user-456")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithKeyId("key-v2")
            .SignWithHmac(keyV2)
            .Build();

        // Day 30: Remove key-v1 from resolver (only key-v2 remains)
        var keys = new Dictionary<string, byte[]>
        {
            ["key-v2"] = keyV2
            // key-v1 removed
        };
        KeyResolver resolver = kid => keys.GetValueOrDefault(kid);

        // Act
        var verifier = new SdJwtVerifier();
        var resultV1 = verifier.TryVerifyPresentation(tokenWithV1.ToPresentation(), resolver);
        var resultV2 = verifier.TryVerifyPresentation(tokenWithV2.ToPresentation(), resolver);

        // Assert - Only key-v2 works, key-v1 tokens fail
        Assert.False(resultV1.IsValid, "key-v1 should fail after removal");
        Assert.Contains(ErrorCode.KeyIdNotFound, resultV1.Errors);

        Assert.True(resultV2.IsValid, $"key-v2 verification failed: {string.Join(", ", resultV2.Errors)}");
    }

    [Fact]
    public void KeyRotation_EmergencyRevocation_ImmediateFailure()
    {
        // Arrange - Simulate compromised key requiring immediate revocation
        var compromisedKey = keyGen.GenerateHmacKey();
        var emergencyKey = keyGen.GenerateHmacKey();

        // Token issued with compromised key
        var compromisedToken = SdJwtBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("admin", true)
            .MakeSelective("admin")
            .WithKeyId("compromised-key")
            .SignWithHmac(compromisedKey)
            .Build();

        // Emergency: Immediately remove compromised key and add new emergency key
        var keys = new Dictionary<string, byte[]>
        {
            ["emergency-key"] = emergencyKey
            // compromised-key NOT present
        };
        KeyResolver resolver = kid => keys.GetValueOrDefault(kid);

        // Act - Attempt to verify compromised token
        var verifier = new SdJwtVerifier();
        var result = verifier.TryVerifyPresentation(compromisedToken.ToPresentation("admin"), resolver);

        // Assert - Compromised token immediately fails
        Assert.False(result.IsValid, "Compromised token should fail verification immediately");
        Assert.Contains(ErrorCode.KeyIdNotFound, result.Errors);
        Assert.Empty(result.DisclosedClaims); // No claims should be disclosed
    }

    [Fact]
    public void KeyRotation_ThreeGenerations_SequentialRotation()
    {
        // Arrange - Simulate v1 → v2 → v3 sequential rotation
        var keyV1 = keyGen.GenerateHmacKey();
        var keyV2 = keyGen.GenerateHmacKey();
        var keyV3 = keyGen.GenerateHmacKey();

        // Generate tokens for each generation
        var tokenV1 = SdJwtBuilder.Create()
            .WithClaim("sub", "user-v1")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("gen", 1)
            .MakeSelective("gen")
            .WithKeyId("key-v1")
            .SignWithHmac(keyV1)
            .Build();

        var tokenV2 = SdJwtBuilder.Create()
            .WithClaim("sub", "user-v2")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("gen", 2)
            .MakeSelective("gen")
            .WithKeyId("key-v2")
            .SignWithHmac(keyV2)
            .Build();

        var tokenV3 = SdJwtBuilder.Create()
            .WithClaim("sub", "user-v3")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
            .WithClaim("gen", 3)
            .MakeSelective("gen")
            .WithKeyId("key-v3")
            .SignWithHmac(keyV3)
            .Build();

        var verifier = new SdJwtVerifier();

        // Phase 1: All three keys active (v1, v2, v3 overlap)
        var keysPhase1 = new Dictionary<string, byte[]>
        {
            ["key-v1"] = keyV1,
            ["key-v2"] = keyV2,
            ["key-v3"] = keyV3
        };
        KeyResolver resolverPhase1 = kid => keysPhase1.GetValueOrDefault(kid);

        var resultV1Phase1 = verifier.TryVerifyPresentation(tokenV1.ToPresentation("gen"), resolverPhase1);
        var resultV2Phase1 = verifier.TryVerifyPresentation(tokenV2.ToPresentation("gen"), resolverPhase1);
        var resultV3Phase1 = verifier.TryVerifyPresentation(tokenV3.ToPresentation("gen"), resolverPhase1);

        Assert.True(resultV1Phase1.IsValid, "v1 should work in phase 1");
        Assert.True(resultV2Phase1.IsValid, "v2 should work in phase 1");
        Assert.True(resultV3Phase1.IsValid, "v3 should work in phase 1");

        // Phase 2: Remove v1 (v2, v3 remain)
        var keysPhase2 = new Dictionary<string, byte[]>
        {
            ["key-v2"] = keyV2,
            ["key-v3"] = keyV3
        };
        KeyResolver resolverPhase2 = kid => keysPhase2.GetValueOrDefault(kid);

        var resultV1Phase2 = verifier.TryVerifyPresentation(tokenV1.ToPresentation("gen"), resolverPhase2);
        var resultV2Phase2 = verifier.TryVerifyPresentation(tokenV2.ToPresentation("gen"), resolverPhase2);
        var resultV3Phase2 = verifier.TryVerifyPresentation(tokenV3.ToPresentation("gen"), resolverPhase2);

        Assert.False(resultV1Phase2.IsValid, "v1 should fail in phase 2");
        Assert.True(resultV2Phase2.IsValid, "v2 should work in phase 2");
        Assert.True(resultV3Phase2.IsValid, "v3 should work in phase 2");

        // Phase 3: Remove v2 (only v3 remains)
        var keysPhase3 = new Dictionary<string, byte[]>
        {
            ["key-v3"] = keyV3
        };
        KeyResolver resolverPhase3 = kid => keysPhase3.GetValueOrDefault(kid);

        var resultV1Phase3 = verifier.TryVerifyPresentation(tokenV1.ToPresentation("gen"), resolverPhase3);
        var resultV2Phase3 = verifier.TryVerifyPresentation(tokenV2.ToPresentation("gen"), resolverPhase3);
        var resultV3Phase3 = verifier.TryVerifyPresentation(tokenV3.ToPresentation("gen"), resolverPhase3);

        // Assert - Only v3 works in final phase
        Assert.False(resultV1Phase3.IsValid, "v1 should fail in phase 3");
        Assert.False(resultV2Phase3.IsValid, "v2 should fail in phase 3");
        Assert.True(resultV3Phase3.IsValid, "v3 should work in phase 3");
        Assert.Equal(3, resultV3Phase3.DisclosedClaims["gen"].GetInt32());
    }
}
