using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.ReplayProtection;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

public class ReplayAdmissionRegressionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_NotConsumeJti_WhenSignatureIsInvalid(bool asynchronous)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var options = new ReplayProtectionOptions { Enabled = true };
        using var cache = new InMemoryJtiCache(options);
        var verifier = SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, options)).Build();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "issuer",
            ["jti"] = "same-jti",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
        };
        var signer = new JwtSigner();
        var bad = signer.CreateJwt(claims, RandomNumberGenerator.GetBytes(32), SignatureAlgorithm.HS256) + "~";
        var good = signer.CreateJwt(claims, key, SignatureAlgorithm.HS256) + "~";
        var rejected = asynchronous ? await verifier.TryVerifyPresentationAsync(bad, key, cancellationToken: TestContext.Current.CancellationToken) : verifier.TryVerifyPresentation(bad, key);
        Assert.False(rejected.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, rejected.Errors);
        var accepted = asynchronous ? await verifier.TryVerifyPresentationAsync(good, key, cancellationToken: TestContext.Current.CancellationToken) : verifier.TryVerifyPresentation(good, key);
        Assert.True(accepted.IsValid);
        var replayed = asynchronous ? await verifier.TryVerifyPresentationAsync(good, key, cancellationToken: TestContext.Current.CancellationToken) : verifier.TryVerifyPresentation(good, key);
        Assert.False(replayed.IsValid);
        Assert.Contains(ErrorCode.ReplayAttack, replayed.Errors);
    }
    [Fact]
    public async Task Should_FailClosedAtCacheCapacity_WithoutReopeningFirstCredential()
    {
        var options = new ReplayProtectionOptions { Enabled = true, MaxCacheEntries = 1 };
        using var cache = new InMemoryJtiCache(options);
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithReplayProtection(new JtiValidator(cache, options))
            .Build();
        var key = RandomNumberGenerator.GetBytes(32);
        var expiration = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var signer = new JwtSigner();
        string CreateToken(string jti) => signer.CreateJwt(new Dictionary<string, object>
        {
            ["iss"] = "issuer",
            ["jti"] = jti,
            ["exp"] = expiration
        }, key, SignatureAlgorithm.HS256) + "~";

        var original = CreateToken("first");
        var newcomer = CreateToken("second");
        var token = TestContext.Current.CancellationToken;

        var firstResult = await verifier.TryVerifyPresentationAsync(original, key, cancellationToken: token);
        Assert.True(firstResult.IsValid, firstResult.ErrorDetails);

        var refused = await verifier.TryVerifyPresentationAsync(newcomer, key, cancellationToken: token);
        Assert.False(refused.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, refused.Errors);
        Assert.False(await cache.ExistsAsync("issuer", "second", token));

        var replay = await verifier.TryVerifyPresentationAsync(original, key, cancellationToken: token);
        Assert.False(replay.IsValid);
        Assert.Contains(ErrorCode.ReplayAttack, replay.Errors);
        Assert.True(await cache.ExistsAsync("issuer", "first", token));
    }

}
