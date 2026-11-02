using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Malformed presentations must not repeatedly allocate verifier audience
/// policy state before any signed input has been admitted.
/// </summary>
public sealed class VerifierAudiencePolicyAllocationTests
{
    [Fact]
    public void Should_NotRebuildLargeAudiencePolicy_WhenPresentationIsMalformed()
    {
        var audiences = Enumerable.Range(0, 10_000)
            .Select(index => $"service-{index}")
            .ToArray();
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedAudiences = audiences
        });
        var key = new byte[32];

        // Warm up the parsing/rejection path outside the measurement.
        Assert.False(verifier.TryVerifyPresentation("not-a-presentation", key).IsValid);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var result = verifier.TryVerifyPresentation("not-a-presentation", key);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.False(result.IsValid);
        Assert.True(allocated < 64 * 1024,
            $"A malformed presentation allocated {allocated} bytes from verifier audience policy.");
    }
}
