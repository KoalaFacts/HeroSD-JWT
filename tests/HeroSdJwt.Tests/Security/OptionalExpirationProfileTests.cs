using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 leaves required validity claims to the application profile.
/// Expiration remains mandatory by default; an explicit profile may use
/// separate lifetime enforcement without ignoring a present exp claim.
/// </summary>
public sealed class OptionalExpirationProfileTests
{
    private static readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    [Fact]
    public void Should_RequireExpirationByDefault_When_ClaimIsAbsent()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"sub":"alice"}""");
        var options = new SdJwtVerificationOptions();

        Assert.True(options.RequireExpiration);
        Assert.False(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }

    [Fact]
    public void Should_AcceptMissingExpiration_When_ProfileExplicitlyAllowsIt()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"sub":"alice","nbf":1799999999,"iat":1799999999}""");
        var options = new SdJwtVerificationOptions
        {
            RequireExpiration = false,
            ClockSkew = TimeSpan.Zero
        };

        Assert.True(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"exp":1799999999}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":"invalid"}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":null}""")]
    public void Should_RejectExpiredOrMalformedExpiration_When_ProfileDoesNotRequirePresence(string json)
    {
        using var document = JsonDocument.Parse(json);
        var options = new SdJwtVerificationOptions
        {
            RequireExpiration = false,
            ClockSkew = TimeSpan.Zero
        };

        Assert.False(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"nbf":1800000060}""")]
    [InlineData(/*lang=json,strict*/ """{"iat":1800000060}""")]
    public void Should_EnforceOtherTemporalClaims_When_ExpirationIsAbsent(string json)
    {
        using var document = JsonDocument.Parse(json);
        var options = new SdJwtVerificationOptions
        {
            RequireExpiration = false,
            ClockSkew = TimeSpan.Zero
        };

        Assert.False(new ClaimValidator().ValidateTemporalClaims(document.RootElement, options, _now));
    }

    [Fact]
    public async Task Should_VerifySignedPresentationWithoutExpiration_When_ProfileExplicitlyAllowsIt()
    {
        byte[] key = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];
        const string header = /*lang=json,strict*/ """{"alg":"HS256","kid":"test-key"}""";
        const string payload = /*lang=json,strict*/ """{"sub":"alice","_sd":[]}""";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(key, System.Text.Encoding.UTF8.GetBytes(signingInput));
        var presentation = signingInput + "." + Base64UrlEncoder.Encode(signature) + "~";

        var strictVerifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
        Assert.False(strictVerifier.TryVerifyPresentation(presentation, key).IsValid);

        var profileVerifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric,
            RequireExpiration = false
        });

        byte[]? Resolve(string keyId)
        {
            return keyId == "test-key" ? key : null;
        }

        var direct = profileVerifier.TryVerifyPresentation(presentation, key);
        var resolved = profileVerifier.TryVerifyPresentation(presentation, Resolve);
        var asyncDirect = await profileVerifier.TryVerifyPresentationAsync(
            presentation, key, cancellationToken: TestContext.Current.CancellationToken);
        var asyncResolved = await profileVerifier.TryVerifyPresentationAsync(
            presentation, Resolve, cancellationToken: TestContext.Current.CancellationToken);

        foreach (var result in new[] { direct, resolved, asyncDirect, asyncResolved })
        {
            Assert.True(result.IsValid, result.ErrorDetails);
        }
    }
}
