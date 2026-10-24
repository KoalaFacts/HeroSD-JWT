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
}
