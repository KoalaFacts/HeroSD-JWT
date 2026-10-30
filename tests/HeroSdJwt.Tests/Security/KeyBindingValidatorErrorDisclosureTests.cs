using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// External holder-proof validators can call KMS or policy services.
/// Backend diagnostics must not escape verification results or exceptions.
/// </summary>
public sealed class KeyBindingValidatorErrorDisclosureTests
{
    private const string BACKEND_DIAGNOSTIC = "sensitive-holder-proof-backend-diagnostic-marker";
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "verifier-challenge";
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_FailClosedWithoutLeaking_WhenCustomKeyBindingValidatorThrows(bool domainException)
    {
        var presentation = CreateValidPresentation();
        var verifier = SdJwtVerifierBuilder.Create()
            .RequireKeyBinding()
            .WithExpectedKeyBindingAudience(AUDIENCE)
            .WithExpectedNonce(NONCE)
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithKeyBindingValidator(new ThrowingKeyBindingValidator(domainException))
            .Build();

        static byte[]? ResolveKey(string kid) =>
            kid == "holder-proof-test-key" ? _issuerKey : null;

        foreach (var useResolver in new[] { false, true })
        {
            var syncResult = useResolver
                ? verifier.TryVerifyPresentation(presentation, ResolveKey)
                : verifier.TryVerifyPresentation(presentation, _issuerKey);

            Assert.False(syncResult.IsValid);
            Assert.Contains(ErrorCode.InvalidSignature, syncResult.Errors);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

            var asyncResult = useResolver
                ? await verifier.TryVerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
                : await verifier.TryVerifyPresentationAsync(
                    presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);

            Assert.False(asyncResult.IsValid);
            Assert.Contains(ErrorCode.InvalidSignature, asyncResult.Errors);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

            var syncException = Assert.Throws<SdJwtException>(() =>
            {
                _ = useResolver
                    ? verifier.VerifyPresentation(presentation, ResolveKey)
                    : verifier.VerifyPresentation(presentation, _issuerKey);
            });
            Assert.Equal(ErrorCode.InvalidSignature, syncException.ErrorCode);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncException.ToString(), StringComparison.Ordinal);

            var asyncException = await Assert.ThrowsAsync<SdJwtException>(async () =>
            {
                _ = useResolver
                    ? await verifier.VerifyPresentationAsync(
                        presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
                    : await verifier.VerifyPresentationAsync(
                        presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
            });
            Assert.Equal(ErrorCode.InvalidSignature, asyncException.ErrorCode);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncException.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Should_PreserveCancellation_WhenCustomKeyBindingValidatorCancels()
    {
        var presentation = CreateValidPresentation();
        var verifier = SdJwtVerifierBuilder.Create()
            .RequireKeyBinding()
            .WithExpectedKeyBindingAudience(AUDIENCE)
            .WithExpectedNonce(NONCE)
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithKeyBindingValidator(new CancelingKeyBindingValidator())
            .Build();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            verifier.VerifyPresentationAsync(
                presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken));
    }

    private static string CreateValidPresentation()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issued = SdJwtIssuerBuilder.Create()
            .WithKeyId("holder-proof-test-key")
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .WithKeyBinding(holder.ExportSubjectPublicKeyInfo())
            .SignWithHmac(_issuerKey)
            .Build();

        var presenter = new SdJwtPresenter();
        var unsignedPresentation = presenter.FormatPresentation(
            presenter.CreatePresentationWithAllClaims(issued));
        var hash = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(unsignedPresentation)));
        var proof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), hash, AUDIENCE, NONCE);
        return presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(issued, proof));
    }

    private sealed class ThrowingKeyBindingValidator(bool domainException) : IKeyBindingValidator
    {
        public bool ValidateKeyBinding(
            string keyBindingJwt,
            byte[] holderPublicKey,
            string expectedSdJwtHash,
            IReadOnlyCollection<string> expectedAudiences,
            string? expectedNonce = null)
        {
            if (domainException)
            {
                throw new SdJwtException(BACKEND_DIAGNOSTIC, ErrorCode.InvalidInput);
            }

            throw new IOException(BACKEND_DIAGNOSTIC);
        }
    }

    private sealed class CancelingKeyBindingValidator : IKeyBindingValidator
    {
        public bool ValidateKeyBinding(
            string keyBindingJwt,
            byte[] holderPublicKey,
            string expectedSdJwtHash,
            IReadOnlyCollection<string> expectedAudiences,
            string? expectedNonce = null) =>
            throw new OperationCanceledException();
    }
}
