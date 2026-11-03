using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A small configured audience allowlist and signed audience array should not
/// rebuild a HashSet for every otherwise valid JWT verification.
/// </summary>
public sealed class SmallAudienceArrayAllocationTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_AvoidAudienceLookupAllocation_WhenBothAudienceSetsAreSmall(bool expectedMatch)
    {
        // The escaped spelling checks matching against the decoded signed
        // StringOrURI rather than comparing raw JSON escape sequences.
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"aud":["service-\u0061","service-b"]}""");
        string[] expectedAudiences = expectedMatch
            ? ["service-a", "other-service"]
            : ["other-service", "third-service"];
        var validator = new ClaimValidator();

        for (var i = 0; i < 64; i++)
        {
            Assert.Equal(expectedMatch, validator.ValidateAudience(document.RootElement, expectedAudiences));
        }

        const int Iterations = 256;
        var matchingResults = 0;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < Iterations; i++)
        {
            if (validator.ValidateAudience(document.RootElement, expectedAudiences) == expectedMatch)
            {
                matchingResults++;
            }
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(Iterations, matchingResults);
        // ValidateAudience must decode every signed entry, including later malformed
        // Unicode, before it can accept an earlier match. This necessarily
        // allocates the decoded strings; the regression is the extra HashSet,
        // not a zero-allocation contract. The safety-preserving implementation
        // measured 208 bytes/call on all nine .NET 8/9/10 CI runners.
        Assert.True(allocated < Iterations * 256L,
            $"Two configured audiences against a two-element signed array allocated {allocated / Iterations} bytes per call.");
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"aud":["service-a",null]}""")]
    [InlineData(/*lang=json,strict*/ """{"aud":["service-a",9]}""")]
    public void Should_RejectMalformedLaterAudience_EvenIfEarlierElementMatches(string payloadJson)
    {
        using var document = JsonDocument.Parse(payloadJson);

        Assert.False(new ClaimValidator().ValidateAudience(
            document.RootElement, ["service-a", "other-service"]));
    }

    [Fact]
    public void Should_RejectSignedAudienceWithInvalidEscapedSurrogate_AfterEarlierAudienceMatch()
    {
        // A valid signature cannot justify ignoring a later malformed aud entry.
        // JsonDocument accepts the escaped lone surrogate into a JSON string;
        // matching the first audience must not short-circuit full validation.
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var header = Encoding.Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"HS256","typ":"JWT"}""");
        var exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var payload = Encoding.Base64UrlEncoder.Encode(
            $$"""{"exp":{{exp}},"aud":["service-a","\uD800"]}""");
        var signingInput = $"{header}.{payload}";
        var signature = System.Security.Cryptography.HMACSHA256.HashData(
            key, System.Text.Encoding.ASCII.GetBytes(signingInput));
        var signedPresentation = $"{signingInput}.{Encoding.Base64UrlEncoder.Encode(signature)}~";
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = Primitives.VerificationKeyType.Symmetric,
            ExpectedAudiences = ["service-a", "other-service"]
        });

        Assert.False(verifier.TryVerifyPresentation(signedPresentation, key).IsValid);
    }

    [Fact]
    public void Should_TreatAllWhitespaceConfiguredAudiencesAsUnconstrained()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"aud":["service-a","service-b"]}""");

        Assert.True(new ClaimValidator().ValidateAudience(document.RootElement, [" ", ""]));
    }
}
