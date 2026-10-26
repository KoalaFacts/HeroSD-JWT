using HeroSdJwt.Issuance;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// JWT validity and identity claims may not be selectively disclosed, even
/// when an individual element of an array-valued claim is selected.
/// </summary>
public class ReservedClaimArrayDisclosureTests
{
    private static readonly byte[] _signingKey = new byte[32];

    [Theory]
    [InlineData("aud", "aud[0]")]
    [InlineData("aud", "aud[1]")]
    [InlineData("iss", "iss[0]")]
    [InlineData("sub", "sub[0]")]
    [InlineData("jti", "jti[0]")]
    [InlineData("nbf", "nbf[0]")]
    [InlineData("iat", "iat[0]")]
    [InlineData("cnf", "cnf[0]")]
    public void Should_RejectArrayElementDisclosureOfReservedClaim(string claimName, string selectedPath)
    {
        var claims = new Dictionary<string, object>
        {
            [claimName] = new[] { "first", "second" },
            ["roles"] = new[] { "reader", "writer" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                claims, [selectedPath], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("cannot be selectively disclosable", exception.Message);
    }

    [Fact]
    public void Should_AllowNonReservedArrayElementDisclosureAlongsideVisibleAudience()
    {
        var claims = new Dictionary<string, object>
        {
            ["aud"] = new[] { "service-a", "service-b" },
            ["roles"] = new[] { "reader", "writer" }
        };

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, ["roles[1]"], _signingKey, HashAlgorithm.Sha256);

        Assert.Single(sdJwt.Disclosures);
    }
}
