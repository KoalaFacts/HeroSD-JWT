using HeroSdJwt.Cryptography;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Application-supplied signature validators may call remote key services.
/// Their backend exceptions must not be copied into public verification results.
/// </summary>
public sealed class SignatureValidatorErrorDisclosureTests
{
    private const string BACKEND_DIAGNOSTIC = "sensitive-signature-backend-diagnostic-marker";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_NotExposeBackendDiagnostics_WhenCustomSignatureValidatorFails(
        bool useResolver, bool domainException)
    {
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId("signature-test-key")
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

        var verifier = new SdJwtVerifier(
            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
            new EcPublicKeyConverter(),
            new FailingSignatureValidator(domainException),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator());

        static byte[]? ResolveKey(string keyId)
        {
            return keyId == "signature-test-key" ? _signingKey : null;
        }

        var syncResult = useResolver
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(syncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, syncResult.Errors);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asyncResult = useResolver
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, asyncResult.Errors);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Should_RedactBackendDiagnostics_WhenCustomValidatorThrowsAlgorithmException(
        bool useResolver, bool confusion)
    {
        // A custom signature provider can wrap a KMS error in a domain-specific
        // algorithm exception. Preserve the error code, not the backend message.
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId("signature-test-key")
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

        var verifier = new SdJwtVerifier(
            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
            new EcPublicKeyConverter(),
            new FailingAlgorithmSignatureValidator(confusion),
            new DigestValidator(),
            new KeyBindingValidator(),
            new ClaimValidator());

        static byte[]? ResolveKey(string keyId)
        {
            return keyId == "signature-test-key" ? _signingKey : null;
        }

        var expectedCode = confusion ? ErrorCode.AlgorithmConfusion : ErrorCode.UnsupportedAlgorithm;

        var syncResult = useResolver
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(syncResult.IsValid);
        Assert.Contains(expectedCode, syncResult.Errors);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var syncError = Assert.ThrowsAny<SdJwtException>(() =>
        {
            if (useResolver)
            {
                verifier.VerifyPresentation(presentation, ResolveKey);
            }
            else
            {
                verifier.VerifyPresentation(presentation, _signingKey);
            }
        });
        Assert.Equal(expectedCode, syncError.ErrorCode);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncError.ToString(), StringComparison.Ordinal);

        var asyncResult = useResolver
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(expectedCode, asyncResult.Errors);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asyncError = await Assert.ThrowsAnyAsync<SdJwtException>(() => useResolver
            ? verifier.VerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.VerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(expectedCode, asyncError.ErrorCode);
        Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncError.ToString(), StringComparison.Ordinal);
    }

    private sealed class FailingAlgorithmSignatureValidator(bool confusion) : ISignatureValidator
    {
        public bool VerifyJwtSignature(string jwt, byte[] publicKey)
        {
            if (confusion)
            {
                throw new AlgorithmConfusionException(BACKEND_DIAGNOSTIC);
            }

            throw new AlgorithmNotSupportedException(BACKEND_DIAGNOSTIC);
        }

        public bool VerifyJwtSignature(string jwt, KeyResolver? keyResolver, byte[]? fallbackKey = null) =>
            VerifyJwtSignature(jwt, fallbackKey ?? _signingKey);
    }

    private sealed class FailingSignatureValidator(bool domainException) : ISignatureValidator
    {
        public bool VerifyJwtSignature(string jwt, byte[] publicKey) => Fail();

        public bool VerifyJwtSignature(string jwt, KeyResolver? keyResolver, byte[]? fallbackKey = null) => Fail();

        private bool Fail()
        {
            if (domainException)
            {
                throw new SdJwtException(BACKEND_DIAGNOSTIC, ErrorCode.InvalidInput);
            }

            throw new IOException(BACKEND_DIAGNOSTIC);
        }
    }
}
