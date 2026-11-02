using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Reject malformed or absent signed audiences before allocating a lookup
/// table for a large verifier-managed allowlist.
/// </summary>
public sealed class DirectAudienceShapePreflightTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ """{}""")]
    [InlineData(/*lang=json,strict*/ """{"aud":42}""")]
    [InlineData(/*lang=json,strict*/ """{"aud":["tenant-0",null]}""")]
    public void Should_RejectMissingOrMalformedAudience_WithoutAllocatingPolicySet(string payloadJson)
    {
        var expectedAudiences = Enumerable.Range(0, 25_000)
            .Select(index => $"tenant-{index}")
            .ToArray();
        using var document = JsonDocument.Parse(payloadJson);
        var validator = new ClaimValidator();

        var before = GC.GetAllocatedBytesForCurrentThread();
        var accepted = validator.ValidateAudience(document.RootElement, expectedAudiences);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.False(accepted);
        Assert.True(allocated < 64 * 1024,
            $"Rejecting a missing or malformed signed audience allocated {allocated} bytes for the verifier policy.");
    }

    [Fact]
    public void Should_TreatWhitespaceOnlyExpectedAudiencesAsUnconfigured_WhenAudienceIsMissing()
    {
        using var document = JsonDocument.Parse("""{"sub":"holder"}""");

        Assert.True(new ClaimValidator().ValidateAudience(
            document.RootElement, ["", " ", "\t"]));
    }
}
