using HeroSdJwt.Encoding;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Key-bound presentations must not reconstruct a large verifier audience lookup
/// on every successful request when the issuer JWT contains a single audience.
/// </summary>
public sealed class KeyBindingAudienceIntersectionAllocationTests
{
    [Fact]
    public void Should_NotRebuildLargeAudienceSet_WhenValidKeyBindingUsesIssuerAudience()
    {
        const string expectedAudience = "service-9999";
        const string expectedNonce = "verifier-challenge";
        var audiences = Enumerable.Range(0, 10_000)
            .Select(index => $"service-{index}")
            .ToArray();
        var issuerKey = RandomNumberGenerator.GetBytes(32);
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var issued = TestHelpers.CreateIssuer().CreateSdJwt(
            new Dictionary<string, object>
            {
                ["sub"] = "holder",
                ["aud"] = expectedAudience
            },
            [],
            issuerKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holder.ExportSubjectPublicKeyInfo());

        var presenter = new SdJwtPresenter();
        var unsigned = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(issued));
        var sdHash = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(unsigned)));
        var keyBinding = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), sdHash, expectedAudience, expectedNonce);
        var presentation = presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(issued, keyBinding));

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedAudiences = audiences,
            RequireKeyBinding = true,
            ExpectedNonce = expectedNonce,
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        // Warm the full ES256 holder-proof path before measuring just one request.
        Assert.True(verifier.TryVerifyPresentation(presentation, issuerKey).IsValid);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var result = verifier.TryVerifyPresentation(presentation, issuerKey);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.True(allocated < 128 * 1024,
            $"A valid key-bound presentation allocated {allocated} bytes rebuilding expected audiences.");
    }
}
