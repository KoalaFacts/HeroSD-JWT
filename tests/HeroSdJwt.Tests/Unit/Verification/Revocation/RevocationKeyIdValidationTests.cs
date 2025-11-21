using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Verification.Revocation;

public class RevocationKeyIdValidationTests
{
    private readonly KeyGenerator _keyGen = KeyGenerator.Instance;

    [Fact]
    public async Task InvalidKid_FailsBeforeRevocationLookup()
    {
        // Arrange
        var signingKey = _keyGen.GenerateHmacKey();
        var presentation = CreatePresentationWithCustomKid("key-\u0001-invalid");

        var trackingStore = new TrackingRevocationStore();
        var verifier = new SdJwtVerifier(
            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Either },
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(TimeProvider.System),
            new ClaimValidator(),
            jtiValidator: null,
            revocationStore: trackingStore);

        // Act
        var result = await verifier.TryVerifyPresentationAsync(
            presentation,
            signingKey,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.KeyIdInvalidCharacters, result.Errors);
        Assert.False(trackingStore.KeyCheckInvoked);
    }

    [Fact]
    public async Task InvalidKid_FailOpenMode_StillShortCircuitsBeforeStore()
    {
        // Arrange
        var signingKey = _keyGen.GenerateHmacKey();
        var presentation = CreatePresentationWithCustomKid(new string('k', 300)); // too long

        var trackingStore = new TrackingRevocationStore();
        var verifier = new SdJwtVerifier(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Either,
                Revocation = new RevocationOptions { FailureMode = RevocationFailureMode.FailOpen }
            },
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(TimeProvider.System),
            new ClaimValidator(),
            jtiValidator: null,
            revocationStore: trackingStore);

        // Act
        var result = await verifier.TryVerifyPresentationAsync(
            presentation,
            signingKey,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.KeyIdTooLong, result.Errors);
        Assert.False(trackingStore.KeyCheckInvoked);
    }

    private sealed class TrackingRevocationStore : IRevocationStore
    {
        public bool KeyCheckInvoked { get; private set; }

        public Task CleanupExpiredEntriesAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<bool> IsJtiRevokedAsync(string jti, CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task<bool> IsKeyRevokedAsync(string keyId, CancellationToken cancellationToken = default)
        {
            KeyCheckInvoked = true;
            return Task.FromResult(false);
        }

        public Task<bool> IsUserRevokedAsync(string userId, CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task RevokeJtiAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeKeyAsync(string keyId, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RevokeUserAsync(string userId, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task UnrevokeKeyAsync(string keyId, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task UnrevokeUserAsync(string userId, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private static string CreatePresentationWithCustomKid(string keyId)
    {
        var headerJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["alg"] = "HS256",
            ["kid"] = keyId
        });

        var payloadJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            ["_sd"] = Array.Empty<string>(),
            ["_sd_alg"] = "sha-256"
        });

        var header = Base64UrlEncoder.Encode(headerJson);
        var payload = Base64UrlEncoder.Encode(payloadJson);
        var signature = Base64UrlEncoder.Encode("sig");

        var jwt = $"{header}.{payload}.{signature}";
        return $"{jwt}~";
    }
}
