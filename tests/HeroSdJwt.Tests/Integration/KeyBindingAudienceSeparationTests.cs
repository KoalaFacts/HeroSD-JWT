using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// RFC 9901 binds a holder-signed KB-JWT to the verifier. Its aud need not
/// match an optional audience in the independently issuer-signed JWT.
/// </summary>
public class KeyBindingAudienceSeparationTests
{
    private const string VerifierAudience = "https://verifier.example.test";
    private const string IssuerAudience = "https://issuer-service.example.test";
    private const string Nonce = "verifier-challenge";

    [Theory]
    [InlineData(null, null, VerifierAudience, true)]
    [InlineData(IssuerAudience, IssuerAudience, VerifierAudience, true)]
    [InlineData(IssuerAudience, "https://wrong-issuer-service.example.test", VerifierAudience, false)]
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
            ExpectedKeyBindingAudience = VerifierAudience,
            ExpectedNonce = Nonce,
            ExpectedKeyType = VerificationKeyType.Symmetric
        };

        var result = TestHelpers.CreateVerifier(options)
            .TryVerifyPresentation(presentation, issuerKey);

        Assert.Equal(expectedValid, result.IsValid);
    }

    [Fact]
    public void Should_ApplySeparateKeyBindingAudienceThroughFluentBuilder()
    {
        var (presentation, issuerKey) = CreatePresentation(null, VerifierAudience);
        var verifier = SdJwtVerifierBuilder.Create()
            .RequireKeyBinding()
            .WithExpectedKeyBindingAudience(VerifierAudience)
            .WithExpectedNonce(Nonce)
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
            ExpectedKeyBindingAudience = VerifierAudience,
            ExpectedNonce = Nonce
        };
        valid.Validate();

        Assert.Throws<ArgumentException>(() => new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedKeyBindingAudience = VerifierAudience
        }.Validate());

        Assert.Throws<ArgumentException>(() => new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedNonce = Nonce
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
            SHA256.HashData(Encoding.UTF8.GetBytes(unsignedPresentation)));
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(),
            digest,
            holderAudience,
            Nonce);

        return (presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(issued, proof)), issuerKey);
    }
}
