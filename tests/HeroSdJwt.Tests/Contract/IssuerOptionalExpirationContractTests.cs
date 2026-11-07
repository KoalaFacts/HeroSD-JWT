using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Issuers may opt out of implicit expiration only for an application-managed
/// lifetime policy; the default issuer and verifier behavior remains unchanged.
/// </summary>
public class IssuerOptionalExpirationContractTests
{
    private static readonly byte[] _signingKey = new byte[32];

    [Fact]
    public async Task Should_RequireExplicitIssuerAndVerifierOptInForMissingExpiration()
    {
        var credential = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "subject-123")
            .WithClaim("email", "holder@example.test")
            .MakeSelective("email")
            .WithoutImplicitExpiration()
            .SignWithHmac(_signingKey)
            .Build();

        using (var document = JsonDocument.Parse(Base64UrlEncoder.DecodeString(credential.Jwt.Split('.')[1])))
        {
            Assert.False(document.RootElement.TryGetProperty("exp", out _));
        }

        var presentation = credential.ToCombinedFormat();
        var strictVerifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();
        Assert.False(strictVerifier.TryVerifyPresentation(presentation, _signingKey).IsValid);

        var profileVerifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .AllowMissingExpiration()
            .Build();
        var syncResult = profileVerifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(syncResult.IsValid, syncResult.ErrorDetails);

        var asyncResult = await profileVerifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    [Fact]
    public void Should_RetainAndValidateExplicitExpirationAfterIssuerOptOut()
    {
        var expiredAt = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var credential = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "subject-123")
            .WithClaim("exp", expiredAt)
            .WithoutImplicitExpiration()
            .SignWithHmac(_signingKey)
            .Build();

        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeString(credential.Jwt.Split('.')[1]));
        Assert.Equal(expiredAt, document.RootElement.GetProperty("exp").GetInt64());

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .AllowMissingExpiration()
            .Build();
        Assert.False(verifier.TryVerifyPresentation(credential.ToCombinedFormat(), _signingKey).IsValid);
    }

    [Fact]
    public void Should_KeepExistingLowLevelIssuerContractWhileAllowingExplicitOptOut()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "subject-123"
        };
        var issuer = TestHelpers.CreateIssuer();
        var withoutExpiration = issuer.CreateSdJwt(
            claims, [], _signingKey, HashAlgorithm.Sha256, SignatureAlgorithm.HS256,
            holderPublicKey: null, decoyDigestCount: 0, keyId: null, addDefaultExpiration: false);
        ISdJwtIssuer legacyContract = issuer;
        var withDefault = legacyContract.CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256);

        using var absentDocument = JsonDocument.Parse(Base64UrlEncoder.DecodeString(withoutExpiration.Jwt.Split('.')[1]));
        using var defaultDocument = JsonDocument.Parse(Base64UrlEncoder.DecodeString(withDefault.Jwt.Split('.')[1]));
        Assert.False(absentDocument.RootElement.TryGetProperty("exp", out _));
        Assert.True(defaultDocument.RootElement.TryGetProperty("exp", out _));
        Assert.False(claims.ContainsKey("exp"));
    }
}
