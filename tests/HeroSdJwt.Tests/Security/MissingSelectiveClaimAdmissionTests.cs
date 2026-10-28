using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Missing caller-selected claims must not silently turn into permanently
/// disclosed values or an incompletely applied issuance policy.
/// </summary>
public class MissingSelectiveClaimAdmissionTests
{
    [Theory]
    [InlineData("missing")]
    [InlineData("missing[0]")]
    [InlineData("missing[1]")]
    public void Should_RejectUnknownSelectedClaim_WhenUsingLowLevelIssuer(string requestedPath)
    {
        var claims = new Dictionary<string, object>
        {
            ["email"] = "private@example.com"
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                claims,
                [requestedPath],
                KeyGenerator.Instance.GenerateHmacKey(),
                HashAlgorithm.Sha256));

        Assert.Contains("missing", exception.Message);
        Assert.Equal("private@example.com", claims["email"]);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("missing[0]")]
    public void Should_RejectUnknownSelectedClaim_WhenOtherSelectionsExist(string requestedPath)
    {
        var claims = new Dictionary<string, object>
        {
            ["email"] = "private@example.com",
            ["roles"] = new[] { "viewer", "editor" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            SdJwtIssuerBuilder.Create()
                .WithClaims(claims)
                .MakeSelective("email", "roles[1]", requestedPath)
                .SignWithHmac(KeyGenerator.Instance.GenerateHmacKey())
                .Build());

        Assert.Contains("missing", exception.Message);
    }

    [Fact]
    public void Should_CreateCredential_WhenSelectedClaimsExist()
    {
        var credential = SdJwtIssuerBuilder.Create()
            .WithClaim("email", "private@example.com")
            .WithClaim("roles", new[] { "viewer", "editor" })
            .MakeSelective("email", "roles[1]")
            .SignWithHmac(KeyGenerator.Instance.GenerateHmacKey())
            .Build();

        Assert.Equal(2, credential.Disclosures.Count);
    }
    [Theory]
    [InlineData("email")]
    [InlineData("roles[0]")]
    public void Should_RejectCaseFoldedClaimPath_WhenCallerDictionaryIgnoresCase(string requestedPath)
    {
        var claims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["Email"] = "private@example.com",
            ["Roles"] = new[] { "viewer", "editor" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            SdJwtIssuerBuilder.Create()
                .WithClaims(claims)
                .MakeSelective(requestedPath)
                .SignWithHmac(KeyGenerator.Instance.GenerateHmacKey())
                .Build());

        Assert.Contains("does not exist", exception.Message);
    }

    [Fact]
    public void Should_AllowExactCaseClaimPaths_WhenCallerDictionaryIgnoresCase()
    {
        var claims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["Email"] = "private@example.com",
            ["Roles"] = new[] { "viewer", "editor" }
        };

        var credential = SdJwtIssuerBuilder.Create()
            .WithClaims(claims)
            .MakeSelective("Email", "Roles[0]")
            .SignWithHmac(KeyGenerator.Instance.GenerateHmacKey())
            .Build();

        Assert.Equal(2, credential.Disclosures.Count);
    }

}
