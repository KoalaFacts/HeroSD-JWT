using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A pluggable digest validator may call a remote digest or policy service.
/// Its diagnostic exceptions must never escape through verification APIs.
/// </summary>
public sealed class DigestValidatorErrorDisclosureTests
{
    private const string BACKEND_DIAGNOSTIC = "sensitive-digest-backend-diagnostic-marker";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("single", false)]
    [InlineData("single", true)]
    [InlineData("all", false)]
    [InlineData("all", true)]
    public async Task Should_NotExposeBackendDiagnostics_WhenCustomDigestValidatorFails(
        string failingStage, bool domainException)
    {
        // Include an object disclosure and an array placeholder so both
        // ValidateDigest (shape checks) and ValidateAllDigests are exercised.
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId("digest-validator-test-key")
            .WithClaim("sub", "subject")
            .WithClaim("email", "alice@example.test")
            .WithClaim("items", new[] { "first", "second" })
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .MakeSelective("email", "items[1]")
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithDigestValidator(new FailingDigestValidator(failingStage, domainException))
            .Build();

        static byte[]? ResolveKey(string keyId)
        {
            return keyId == "digest-validator-test-key" ? _signingKey : null;
        }

        foreach (var useResolver in new[] { false, true })
        {
            var syncResult = useResolver
                ? verifier.TryVerifyPresentation(presentation, ResolveKey)
                : verifier.TryVerifyPresentation(presentation, _signingKey);

            Assert.False(syncResult.IsValid);
            Assert.Contains(ErrorCode.DigestMismatch, syncResult.Errors);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

            var asyncResult = useResolver
                ? await verifier.TryVerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
                : await verifier.TryVerifyPresentationAsync(
                    presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

            Assert.False(asyncResult.IsValid);
            Assert.Contains(ErrorCode.DigestMismatch, asyncResult.Errors);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

            var syncException = Assert.Throws<SdJwtException>(() =>
            {
                _ = useResolver
                    ? verifier.VerifyPresentation(presentation, ResolveKey)
                    : verifier.VerifyPresentation(presentation, _signingKey);
            });
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncException.ToString(), StringComparison.Ordinal);

            var asyncException = await Assert.ThrowsAsync<SdJwtException>(async () =>
            {
                _ = useResolver
                    ? await verifier.VerifyPresentationAsync(
                        presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
                    : await verifier.VerifyPresentationAsync(
                        presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
            });
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncException.ToString(), StringComparison.Ordinal);
        }
    }

    private sealed class FailingDigestValidator(string failingStage, bool domainException) : IDigestValidator
    {
        public bool ValidateDigest(string disclosure, Digest expectedDigest, HashAlgorithm algorithm)
        {
            if (failingStage == "single")
            {
                return Fail();
            }

            return false;
        }

        public bool ValidateAllDigests(
            IReadOnlyList<string> disclosures,
            IReadOnlyList<Digest> expectedDigests,
            HashAlgorithm algorithm)
        {
            if (failingStage == "all")
            {
                return Fail();
            }

            return true;
        }

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
