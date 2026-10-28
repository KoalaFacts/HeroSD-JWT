using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// RFC 9901 binds a holder-signed KB-JWT to the verifier. Its aud need not
/// match an optional audience in the independently issuer-signed JWT.
/// </summary>
public class KeyBindingAudienceSeparationTests
{
    private const string VERIFIER_AUDIENCE = "https://verifier.example.test";
    private const string ISSUER_AUDIENCE = "https://issuer-service.example.test";
    private const string NONCE = "verifier-challenge";

    [Theory]
    [InlineData(null, null, VERIFIER_AUDIENCE, true)]
    [InlineData(ISSUER_AUDIENCE, ISSUER_AUDIENCE, VERIFIER_AUDIENCE, true)]
    [InlineData(ISSUER_AUDIENCE, "https://wrong-issuer-service.example.test", VERIFIER_AUDIENCE, false)]
    [InlineData(null, null, "https://other-verifier.example.test", false)]
    public void Should_ValidateIssuerAndKeyBindingAudiencesIndependently(
        string? issuerAudience,
        string? expectedIssuerAudience,
        string holderAudience,
        bool expectedValid)
    {
        var (presentation, issuerKey) = CreatePresentation(issuerAudience, holderAudience);
        var options = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = expectedIssuerAudience,
            ExpectedKeyBindingAudience = VERIFIER_AUDIENCE,
            ExpectedNonce = NONCE,
            ExpectedKeyType = VerificationKeyType.Symmetric
        };

        var result = TestHelpers.CreateVerifier(options)
            .TryVerifyPresentation(presentation, issuerKey);

        Assert.Equal(expectedValid, result.IsValid);
    }

    [Fact]
    public void Should_ApplySeparateKeyBindingAudienceThroughFluentBuilder()
    {
        var (presentation, issuerKey) = CreatePresentation(null, VERIFIER_AUDIENCE);
        var verifier = SdJwtVerifierBuilder.Create()
            .RequireKeyBinding()
            .WithExpectedKeyBindingAudience(VERIFIER_AUDIENCE)
            .WithExpectedNonce(NONCE)
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        Assert.True(verifier.TryVerifyPresentation(presentation, issuerKey).IsValid);
    }

    [Fact]
    public void Should_RequireAnAudienceAndNonceForKeyBindingPolicy()
    {
        var valid = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedKeyBindingAudience = VERIFIER_AUDIENCE,
            ExpectedNonce = NONCE
        };
        valid.Validate();

        Assert.Throws<ArgumentException>(() => new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedKeyBindingAudience = VERIFIER_AUDIENCE
        }.Validate());

        Assert.Throws<ArgumentException>(() => new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedNonce = NONCE
        }.Validate());
    }

    private static (string Presentation, byte[] IssuerKey) CreatePresentation(
        string? issuerAudience,
        string holderAudience)
    {
        var issuerKey = RandomNumberGenerator.GetBytes(32);
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var claims = new Dictionary<string, object> { ["sub"] = "holder-subject" };
        if (issuerAudience != null)
        {
            claims["aud"] = issuerAudience;
        }

        var issued = TestHelpers.CreateIssuer().CreateSdJwt(
            claims,
            [],
            issuerKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holder.ExportSubjectPublicKeyInfo());

        var presenter = new SdJwtPresenter();
        var unsignedPresentation = presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(issued));

        var digest = Base64UrlEncoder.Encode(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(unsignedPresentation)));
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(),
            digest,
            holderAudience,
            NONCE);

        return (presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(issued, proof)), issuerKey);
    }
}
