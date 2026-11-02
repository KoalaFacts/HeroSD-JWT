using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Cancellation from an application-supplied signature provider is not a bad
/// signature. Throwing verification APIs must preserve that distinction.
/// </summary>
public sealed class SignatureProviderCancellationTests
{
    private const string KEY_ID = "canceled-signature-provider";
    private const string BACKEND_DIAGNOSTIC = "secret-kms-cancellation-detail";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_PropagateSignatureProviderCancellation_ThroughThrowingApis(bool resolveKey)
    {
        var verifier = CreateVerifier();
        var presentation = CreatePresentation();

        if (resolveKey)
        {
            Assert.ThrowsAny<OperationCanceledException>(() =>
                verifier.VerifyPresentation(presentation, ResolveKey));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                verifier.VerifyPresentationAsync(presentation, ResolveKey));
        }
        else
        {
            Assert.ThrowsAny<OperationCanceledException>(() =>
                verifier.VerifyPresentation(presentation, _signingKey));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                verifier.VerifyPresentationAsync(presentation, _signingKey));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_FailClosedWithoutLeakingCancellationDetails_ThroughTryApis(bool resolveKey)
    {
        var verifier = CreateVerifier();
        var presentation = CreatePresentation();

        var synchronous = resolveKey
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(synchronous.IsValid);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, synchronous.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asynchronous = resolveKey
            ? await verifier.TryVerifyPresentationAsync(presentation, ResolveKey)
            : await verifier.TryVerifyPresentationAsync(presentation, _signingKey);

        Assert.False(asynchronous.IsValid);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asynchronous.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
    }

    private static SdJwtVerifier CreateVerifier() =>
        new(
            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
            new EcPublicKeyConverter(),
            new CancelingSignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator());

    private static byte[]? ResolveKey(string keyId) =>
        keyId == KEY_ID ? _signingKey : null;

    private static string CreatePresentation() =>
        SdJwtIssuerBuilder.Create()
            .WithKeyId(KEY_ID)
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

    private sealed class CancelingSignatureValidator : ISignatureValidator
    {
        public bool VerifyJwtSignature(string jwt, byte[] publicKey) =>
            throw new OperationCanceledException(BACKEND_DIAGNOSTIC);

        public bool VerifyJwtSignature(
            string jwt, KeyResolver? keyResolver, byte[]? fallbackKey = null) =>
            throw new OperationCanceledException(BACKEND_DIAGNOSTIC);
    }
}
