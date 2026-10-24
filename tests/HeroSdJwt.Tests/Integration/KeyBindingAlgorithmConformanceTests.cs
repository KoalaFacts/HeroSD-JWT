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
/// RFC 9901 key-binding digest and JOSE algorithm conformance tests.
/// </summary>
public class KeyBindingAlgorithmConformanceTests
{
    private const string Audience = "https://verifier.example.test";
    private const string Nonce = "nonce-conformance";

    [Theory]
    [InlineData(HashAlgorithm.Sha256)]
    [InlineData(HashAlgorithm.Sha384)]
    [InlineData(HashAlgorithm.Sha512)]
    public void Should_UseDisclosureHashAlgorithmForKeyBinding(HashAlgorithm disclosureAlgorithm)
    {
        var issuerKey = new byte[32];
        RandomNumberGenerator.Fill(issuerKey);

        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holder.ExportECPrivateKey();
        var holderPublicKey = holder.ExportSubjectPublicKeyInfo();

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            new Dictionary<string, object>
            {
                ["sub"] = "holder-123",
                ["aud"] = Audience,
                ["department"] = "Security"
            },
            ["department"],
            issuerKey,
            disclosureAlgorithm,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        var presenter = new SdJwtPresenter();
        var withoutBinding = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(sdJwt));
        var digestInput = Encoding.ASCII.GetBytes(withoutBinding);
        var expectedHash = disclosureAlgorithm switch
        {
            HashAlgorithm.Sha256 => SHA256.HashData(digestInput),
            HashAlgorithm.Sha384 => SHA384.HashData(digestInput),
            HashAlgorithm.Sha512 => SHA512.HashData(digestInput),
            _ => throw new InvalidOperationException("Unsupported test algorithm")
        };

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = Audience,
            ExpectedNonce = Nonce,
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        var generator = new KeyBindingGenerator();
        var correctBinding = generator.CreateKeyBindingJwt(
            holderPrivateKey, Base64UrlEncoder.Encode(expectedHash), Audience, Nonce);
        var correctPresentation = presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(sdJwt, correctBinding));
        var validResult = verifier.TryVerifyPresentation(correctPresentation, issuerKey);
        Assert.True(validResult.IsValid, $"Valid {disclosureAlgorithm} key binding rejected: {string.Join(", ", validResult.Errors)}");

        if (disclosureAlgorithm != HashAlgorithm.Sha256)
        {
            var incorrectSha256Hash = Base64UrlEncoder.Encode(SHA256.HashData(digestInput));
            var wrongBinding = generator.CreateKeyBindingJwt(
                holderPrivateKey, incorrectSha256Hash, Audience, Nonce);
            var wrongPresentation = presenter.FormatPresentation(
                presenter.CreatePresentationWithAllClaims(sdJwt, wrongBinding));
            var wrongResult = verifier.TryVerifyPresentation(wrongPresentation, issuerKey);
            Assert.False(wrongResult.IsValid);
            Assert.Contains(ErrorCode.InvalidSignature, wrongResult.Errors);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES384")]
    public void Should_RejectContradictoryKeyBindingHeaderDespiteValidEs256Signature(string? declaredAlgorithm)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = holder.ExportECPrivateKey();
        var publicKey = holder.ExportSubjectPublicKeyInfo();

        var expectedHash = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes("signed.jwt~")));
        var legitimate = new KeyBindingGenerator().CreateKeyBindingJwt(
            privateKey, expectedHash, Audience, Nonce);
        var parts = legitimate.Split('.');
        var header = declaredAlgorithm == null
            ? "{\"typ\":\"kb+jwt\"}"
            : $"{{\"alg\":\"{declaredAlgorithm}\",\"typ\":\"kb+jwt\"}}";
        var signedInput = $"{Base64UrlEncoder.Encode(header)}.{parts[1]}";
        var signature = holder.SignData(Encoding.ASCII.GetBytes(signedInput), HashAlgorithmName.SHA256);
        var altered = $"{signedInput}.{Base64UrlEncoder.Encode(signature)}";

        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            altered, publicKey, expectedHash, Audience, Nonce));
    }
}
