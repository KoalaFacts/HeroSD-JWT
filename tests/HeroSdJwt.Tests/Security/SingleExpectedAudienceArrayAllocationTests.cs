using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The common single expected audience must not allocate a lookup table
/// just because the signed JWT uses the array form of the aud claim.
/// </summary>
public sealed class SingleExpectedAudienceArrayAllocationTests
{
    [Theory]
    [InlineData("service-b", true)]
    [InlineData("service-c", false)]
    public void Should_NotAllocateAudienceHashSet_ForSingleExpectedAudience(string expectedAudience, bool expectedMatch)
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"aud":["service-a","service-b"]}""");
        var validator = new ClaimValidator();

        // Warm up both parsing and successful/rejected validation before
        // measuring the steady-state allocation of this public API.
        for (var i = 0; i < 32; i++)
        {
            Assert.Equal(expectedMatch, validator.ValidateAudience(document.RootElement, expectedAudience));
        }

        const int Iterations = 256;
        var correctResults = 0;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < Iterations; i++)
        {
            if (validator.ValidateAudience(document.RootElement, expectedAudience) == expectedMatch)
            {
                correctResults++;
            }
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(Iterations, correctResults);
        Assert.True(allocated < Iterations * 256L,
            $"Validating a two-element signed audience array allocated {allocated / Iterations} bytes per call.");
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_RejectMalformedEscapedUnicodeInLaterAudience_WhenPolicyIsSingleOrAbsent(bool hasExpectedAudience)
    {
        // JSON accepts this escaped lone surrogate, but it is not a valid
        // StringOrURI audience. Earlier matches must not skip checking it.
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"aud":["service-a","\uD800"]}""");
        string[] expectedAudiences = hasExpectedAudience ? ["service-a"] : [];

        Assert.False(new ClaimValidator().ValidateAudience(document.RootElement, expectedAudiences));
    }

}
