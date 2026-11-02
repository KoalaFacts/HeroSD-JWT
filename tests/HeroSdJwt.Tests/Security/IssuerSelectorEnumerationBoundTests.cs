using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The low-level issuer accepts lazy claim selectors. Repeated entries must
/// not allow an unbounded enumerable to keep an issuance operation alive forever.
/// </summary>
public class IssuerSelectorEnumerationBoundTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Repeat((byte)0x53, 32)];

    [Fact]
    public void Should_StopUnboundedDuplicateSelectorStream_BeforeSigning()
    {
        var claims = new Dictionary<string, object>
        {
            ["email"] = "alice@example.test"
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                claims,
                UnboundedDuplicateSelectors(),
                _signingKey,
                HashAlgorithm.Sha256));

        Assert.Equal("selectivelyDisclosableClaims", exception.ParamName);
    }

    private static IEnumerable<string> UnboundedDuplicateSelectors()
    {
        // A finite safety sentinel makes the regression deterministic: the
        // original implementation reads past one million duplicate selectors,
        // whereas the hardened issuer must reject the stream before this throw.
        for (var i = 0; i <= 1_000_000; i++)
        {
            yield return "email";
        }

        throw new InvalidOperationException(
            "Issuer consumed an unbounded duplicate selector stream.");
    }
}
