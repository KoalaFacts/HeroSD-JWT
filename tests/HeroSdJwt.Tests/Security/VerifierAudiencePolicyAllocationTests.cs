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

    [Fact]
    public void Should_VerifySignedAudienceWithoutRebuildingPolicy_WhenNoKeyBinding()
    {
        var audiences = Enumerable.Range(0, 10_000)
            .Select(index => $"service-{index}")
            .ToArray();
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var issued = TestHelpers.CreateIssuer().CreateSdJwt(
            new Dictionary<string, object> { ["aud"] = "service-9999", ["sub"] = "holder" },
            [],
            key,
            HeroSdJwt.Primitives.HashAlgorithm.Sha256,
            HeroSdJwt.Primitives.SignatureAlgorithm.HS256);
        var presentation = issued.ToCombinedFormat();
        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedAudiences = audiences,
            ExpectedKeyType = HeroSdJwt.Primitives.VerificationKeyType.Symmetric
        });

        // A valid signature and audience take the complete no-key-binding path.
        Assert.True(verifier.TryVerifyPresentation(presentation, key).IsValid);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var result = verifier.TryVerifyPresentation(presentation, key);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(result.IsValid);
        Assert.True(allocated < 64 * 1024,
            $"Valid unbound presentation allocated {allocated} bytes rebuilding audience policy.");
    }
}
