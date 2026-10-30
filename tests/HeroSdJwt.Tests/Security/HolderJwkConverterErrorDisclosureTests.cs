using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// An injected JWK converter may use a remote key service. Its diagnostic
/// exceptions must not be copied into publicly visible verification results.
/// </summary>
public sealed class HolderJwkConverterErrorDisclosureTests
{
    private const string BACKEND_DIAGNOSTIC = "sensitive-holder-jwk-converter-backend-diagnostic";
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "verifier-challenge";
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_FailClosedWithoutLeaking_WhenHolderJwkConverterThrows(bool useResolver)
    {
        var presentation = CreateSignedPresentation();
        var verifier = new SdJwtVerifier(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric,
                RequireKeyBinding = true,
                ExpectedKeyBindingAudience = AUDIENCE,
                ExpectedNonce = NONCE
            },
            new ThrowingJwkConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator());

        static byte[]? ResolveKey(string keyId) =>
            keyId == "issuer-key" ? _issuerKey : null;

        var result = useResolver
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, result.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asyncResult = useResolver
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var exception = Assert.Throws<SdJwtException>(() =>
        {
            _ = useResolver
                ? verifier.VerifyPresentation(presentation, ResolveKey)
                : verifier.VerifyPresentation(presentation, _issuerKey);
        });
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, exception.ToString(), StringComparison.Ordinal);

        var asyncException = await Assert.ThrowsAsync<SdJwtException>(async () =>
        {
            _ = useResolver
                ? await verifier.VerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
                : await verifier.VerifyPresentationAsync(
                    presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        });
        Assert.Equal(ErrorCode.InvalidInput, asyncException.ErrorCode);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncException.ToString(), StringComparison.Ordinal);
    }

    private static string CreateSignedPresentation()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issued = SdJwtIssuerBuilder.Create()
            .WithKeyId("issuer-key")
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .WithKeyBinding(holder.ExportSubjectPublicKeyInfo())
            .SignWithHmac(_issuerKey)
            .Build();

        var presenter = new SdJwtPresenter();
        var unsignedPresentation = presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(issued));
        var hash = Base64UrlEncoder.Encode(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(unsignedPresentation)));
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), hash, AUDIENCE, NONCE);
        return presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(issued, proof));
    }

    private sealed class ThrowingJwkConverter : IEcPublicKeyConverter
    {
        public Dictionary<string, object> ToJwk(byte[] publicKeyBytes) =>
            throw new NotSupportedException();

        public byte[] FromJwk(JsonElement jwk) =>
            throw new ArgumentException(BACKEND_DIAGNOSTIC);

        public byte[] FromJwkObject(object jwkObject) =>
            throw new NotSupportedException();
    }
}
