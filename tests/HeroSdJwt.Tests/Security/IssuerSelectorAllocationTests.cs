using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Repeated holder-selectable paths must not consume memory proportional to
/// the number of duplicate entries supplied to the issuer.
/// </summary>
public class IssuerSelectorAllocationTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Repeat((byte)0x51, 32)];

    [Fact]
    public void Should_NotRetainEveryDuplicateSelector_When_IssuingCredential()
    {
        // The credential contains only one Disclosure in both cases.
        // Avoid a large transient List of identical selectors before deduplication.
        _ = MeasureAllocation(1); // JIT warm-up
        var singleSelectorBytes = MeasureAllocation(1);
        var repeatedSelectorBytes = MeasureAllocation(131_072);

        Assert.True(
            repeatedSelectorBytes <= singleSelectorBytes + 256 * 1024,
            $"Repeated selectors allocated {repeatedSelectorBytes:N0} bytes; " +
            $"one selector allocated {singleSelectorBytes:N0} bytes.");
    }

    [Fact]
    public void Should_PreserveMoreThanPresentationLimitDistinctSelectors_When_IssuingCredential()
    {
        // MAX_DISCLOSURES constrains presentations, not an issuer credential
        // whose holder can disclose only the required subset.
        var claims = new Dictionary<string, object> { ["sub"] = "user-1" };
        var selectors = new List<string>();
        for (var i = 0; i <= Constants.MAX_DISCLOSURES; i++)
        {
            var name = $"claim{i}";
            claims.Add(name, i);
            selectors.Add(name);
        }

        var credential = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, selectors, _signingKey, HashAlgorithm.Sha256);

        Assert.Equal(Constants.MAX_DISCLOSURES + 1, credential.Disclosures.Count);
    }

    private static long MeasureAllocation(int count)
    {
        var issuer = TestHelpers.CreateIssuer();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-1",
            ["email"] = "alice@example.test"
        };

        var before = GC.GetAllocatedBytesForCurrentThread();
        var credential = issuer.CreateSdJwt(
            claims,
            Enumerable.Repeat("email", count),
            _signingKey,
            HashAlgorithm.Sha256);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Single(credential.Disclosures);
        GC.KeepAlive(credential);
        return allocated;
    }
}
