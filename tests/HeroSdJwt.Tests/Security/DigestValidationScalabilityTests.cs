using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Verification;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Large but bounded disclosure sets must not allocate per digest comparison.
/// </summary>
public class DigestValidationScalabilityTests
{
    [Fact]
    public void Should_KeepAllocationsBounded_WhenManySignedDigestsArePresent()
    {
        const int disclosureCount = 48;
        const int decoyCount = 850;
        var calculator = new DigestCalculator();
        var disclosures = Enumerable.Range(0, disclosureCount)
            .Select(i => Base64UrlEncoder.Encode($"[\"salt-{i}\",\"claim-{i}\",\"value-{i}\"]"))
            .ToArray();

        // The real digests are at the end of the signed list, as can happen
        // with many issuer decoys. Setup allocations are excluded below.
        var expected = Enumerable.Range(0, decoyCount)
            .Select(i => new Digest(
                calculator.ComputeDigest(
                    Base64UrlEncoder.Encode($"[\"decoy-salt-{i}\",\"decoy-{i}\"]"),
                    HashAlgorithm.Sha256),
                HashAlgorithm.Sha256))
            .Concat(disclosures.Select(d => new Digest(
                calculator.ComputeDigest(d, HashAlgorithm.Sha256),
                HashAlgorithm.Sha256)))
            .ToArray();

        var validator = new DigestValidator(calculator);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var isValid = validator.ValidateAllDigests(disclosures, expected, HashAlgorithm.Sha256);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(isValid);
        Assert.True(allocated < 512 * 1024,
            $"Digest validation allocated {allocated} bytes for {disclosureCount} disclosures and {expected.Length} expected digests.");
    }

    [Fact]
    public void Should_PreservePaddedDigestAliases_WhenUsingLargeExpectedSet()
    {
        const int disclosureCount = 8;
        var calculator = new DigestCalculator();
        var disclosures = Enumerable.Range(0, disclosureCount)
            .Select(i => Base64UrlEncoder.Encode($"[\"salt-{i}\",\"claim-{i}\",\"value-{i}\"]"))
            .ToArray();

        var expected = Enumerable.Range(0, 40)
            .Select(i => new Digest(
                calculator.ComputeDigest($"decoy-{i}", HashAlgorithm.Sha256),
                HashAlgorithm.Sha256))
            .Concat(disclosures.Select((d, i) => new Digest(
                calculator.ComputeDigest(d, HashAlgorithm.Sha256) + (i == 0 ? "=" : ""),
                HashAlgorithm.Sha256)))
            .ToArray();

        Assert.True(new DigestValidator(calculator).ValidateAllDigests(
            disclosures, expected, HashAlgorithm.Sha256));
    }
}
