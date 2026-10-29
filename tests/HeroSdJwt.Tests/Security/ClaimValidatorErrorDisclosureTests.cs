using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Custom claim validators can call external policy services. Their exception
/// details must not be exposed through verification results or throwing APIs.
/// </summary>
public sealed class ClaimValidatorErrorDisclosureTests
{
    private const string BACKEND_DIAGNOSTIC = "sensitive-claim-policy-diagnostic-marker";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("temporal", false)]
    [InlineData("temporal", true)]
    [InlineData("issuer", false)]
    [InlineData("issuer", true)]
    [InlineData("audience", false)]
    [InlineData("audience", true)]
    public async Task Should_NotExposeBackendDiagnostics_WhenCustomClaimValidatorFails(
        string failingStage, bool domainException)
    {
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId("claim-validator-test-key")
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToCombinedFormat();

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithClaimValidator(new FailingClaimValidator(failingStage, domainException))
            .Build();

        static byte[]? ResolveKey(string keyId) =>
            keyId == "claim-validator-test-key" ? _signingKey : null;

        foreach (var useResolver in new[] { false, true })
        {
            var syncResult = useResolver
                ? verifier.TryVerifyPresentation(presentation, ResolveKey)
                : verifier.TryVerifyPresentation(presentation, _signingKey);

            Assert.False(syncResult.IsValid);
            Assert.Contains(ErrorCode.InvalidInput, syncResult.Errors);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

            var asyncResult = useResolver
                ? await verifier.TryVerifyPresentationAsync(
                    presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
                : await verifier.TryVerifyPresentationAsync(
                    presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

            Assert.False(asyncResult.IsValid);
            Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

            var syncException = Assert.Throws<SdJwtException>(() =>
            {
                if (useResolver)
                {
                    _ = verifier.VerifyPresentation(presentation, ResolveKey);
                }
                else
                {
                    _ = verifier.VerifyPresentation(presentation, _signingKey);
                }
            });
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, syncException.ToString(), StringComparison.Ordinal);

            var asyncException = await Assert.ThrowsAsync<SdJwtException>(async () =>
            {
                if (useResolver)
                {
                    _ = await verifier.VerifyPresentationAsync(
                        presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
                }
                else
                {
                    _ = await verifier.VerifyPresentationAsync(
                        presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
                }
            });
            Assert.DoesNotContain(BACKEND_DIAGNOSTIC, asyncException.ToString(), StringComparison.Ordinal);
        }
    }

    private sealed class FailingClaimValidator(string failingStage, bool domainException) : IClaimValidator
    {
        private readonly ClaimValidator _defaultValidator = new();

        public bool ValidateTemporalClaims(
            JsonElement payload, SdJwtVerificationOptions options, DateTimeOffset? currentTime = null) =>
            failingStage == "temporal"
                ? Fail()
                : _defaultValidator.ValidateTemporalClaims(payload, options, currentTime);

        public bool ValidateIssuer(JsonElement payload, string? expectedIssuer) =>
            failingStage == "issuer"
                ? Fail()
                : _defaultValidator.ValidateIssuer(payload, expectedIssuer);

        public bool ValidateAudience(JsonElement payload, IReadOnlyCollection<string>? expectedAudiences) =>
            failingStage == "audience"
                ? Fail()
                : _defaultValidator.ValidateAudience(payload, expectedAudiences);

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
