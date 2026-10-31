using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The verifier borrows parsed JSON during validation; retaining an undisposed
/// JsonDocument on every request unnecessarily holds pooled JSON buffers alive.
/// </summary>
public sealed class VerifierJsonDocumentLifetimeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_ReleaseBorrowedPayloadDocument_AndRetainVerifiedClaims(bool useKeyResolver)
    {
        var issued = SdJwtIssuerBuilder.Create()
            .WithClaim("email", "alice@example.com")
            .WithKeyId("borrowed-payload-test")
            .MakeSelective("email")
            .SignWithHmac(_signingKey)
            .Build();

        var capturingValidator = new CapturingClaimValidator();
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .WithClaimValidator(capturingValidator)
            .Build();

        var presentation = issued.ToCombinedFormat();
        var result = useKeyResolver
            ? verifier.TryVerifyPresentation(
                presentation,
                keyId => keyId == "borrowed-payload-test" ? _signingKey : null)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.True(result.IsValid);
        Assert.Equal("alice@example.com", result.DisclosedClaims["email"].GetString());
        Assert.Equal(JsonValueKind.Object, capturingValidator.BorrowedPayload.ValueKind);

        // The validator must clone a JsonElement if it needs to retain it.
        // The public VerificationResult owns its verified values separately.
        Assert.Throws<ObjectDisposedException>(() =>
        {
            _ = capturingValidator.BorrowedPayload.GetRawText();
        });
        Assert.Equal("alice@example.com", result.DisclosedClaims["email"].GetString());
    }

    private sealed class CapturingClaimValidator : IClaimValidator
    {
        private readonly ClaimValidator _inner = new();

        public JsonElement BorrowedPayload { get; private set; }

        public bool ValidateTemporalClaims(
            JsonElement payload,
            SdJwtVerificationOptions options,
            DateTimeOffset? currentTime = null)
        {
            BorrowedPayload = payload;
            return _inner.ValidateTemporalClaims(payload, options, currentTime);
        }

        public bool ValidateIssuer(JsonElement payload, string? expectedIssuer) =>
            _inner.ValidateIssuer(payload, expectedIssuer);

        public bool ValidateAudience(JsonElement payload, IReadOnlyCollection<string>? expectedAudiences) =>
            _inner.ValidateAudience(payload, expectedAudiences);
    }
}
