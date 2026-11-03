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
        Assert.True(allocated < Iterations * 128L,
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
    public void Should_TreatAllWhitespaceConfiguredAudiencesAsUnconstrained()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"aud":["service-a","service-b"]}""");

        Assert.True(new ClaimValidator().ValidateAudience(document.RootElement, [" ", ""]));
    }
}
