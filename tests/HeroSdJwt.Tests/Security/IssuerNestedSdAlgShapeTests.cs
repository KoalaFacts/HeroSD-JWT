using HeroSdJwt.Issuance;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 reserves _sd_alg for the top-level SD-JWT payload. User-provided
/// nested structures must not bypass the issuer's placement validation simply
/// because their CLR representation is not Dictionary&lt;string, object&gt;.
/// </summary>
public class IssuerNestedSdAlgShapeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectNestedSdAlgInAnonymousObjects()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { location = new { _sd_alg = "sha-512" } }
        };

        AssertRejected(claims);
    }

    [Fact]
    public void Should_RejectNestedSdAlgInJsonElement()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ "{\"address\":[{\"_sd_alg\":\"sha-256\"}]}");
        var claims = new Dictionary<string, object>
        {
            ["profile"] = document.RootElement.Clone()
        };

        AssertRejected(claims);
    }

    [Fact]
    public void Should_RejectNestedSdAlgInDictionaryWithStringValues()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new Dictionary<string, string>
            {
                ["_sd_alg"] = "sha-512"
            }
        };

        AssertRejected(claims);
    }

    [Fact]
    public void Should_RejectNestedSdAlgInsideObjectArrays()
    {
        var claims = new Dictionary<string, object>
        {
            ["permissions"] = new[] { new { _sd_alg = "sha-256" } }
        };

        AssertRejected(claims);
    }

    [Fact]
    public void Should_RejectNestedSdAlgEvenWhenItsPathIsSelectedForDisclosure()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { _sd_alg = "sha-512", display = "Alice" }
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                claims, ["profile._sd_alg"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("_sd_alg", exception.Message);
    }

    [Fact]
    public void Should_RejectNestedSdAlgInNonListEnumerableRuntimeValue()
    {
        var nestedDictionary = new Dictionary<string, object>
        {
            ["_sd_alg"] = "sha-256"
        };
        var collection = new HashSet<System.Collections.IEnumerable>
        {
            nestedDictionary
        };
        var claims = new Dictionary<string, object>
        {
            ["profile"] = collection
        };

        AssertRejected(claims);
    }

    [Fact]
    public void Should_RejectCyclicSelectiveClaimWithoutStackOverflow()
    {
        var profile = new Dictionary<string, object>();
        profile["self"] = profile;

        var claims = new Dictionary<string, object>
        {
            ["profile"] = profile
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                claims, ["profile"], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("nesting", exception.Message);
    }

    [Fact]
    public void Should_AllowNormalAnonymousNestedObjectsAndArrays()
    {
        var claims = new Dictionary<string, object>
        {
            ["profile"] = new { display = "Alice", preferences = new[] { "red", "blue" } }
        };

        var result = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, [], _signingKey, HashAlgorithm.Sha256);

        Assert.NotEmpty(result.Jwt);
        Assert.Empty(result.Disclosures);
    }

    [Fact]
    public void Should_AllowNonSelectiveMultidimensionalArray()
    {
        var claims = new Dictionary<string, object>
        {
            ["matrix"] = new int[,] { { 1, 2 }, { 3, 4 } }
        };

        var result = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, [], _signingKey, HashAlgorithm.Sha256);

        Assert.NotEmpty(result.Jwt);
        Assert.Empty(result.Disclosures);
    }

    [Fact]
    public void Should_RejectNestedSdAlgInMultidimensionalObjectArray()
    {
        var claims = new Dictionary<string, object>
        {
            ["matrix"] = new object[,] { { new Dictionary<string, object> { ["_sd_alg"] = "sha-256" } } }
        };

        AssertRejected(claims);
    }

    [Fact]
    public void Should_AllowLargeNonSelectiveStringClaim()
    {
        var claims = new Dictionary<string, object>
        {
            ["description"] = new string('a', 64 * 1024)
        };

        var result = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, [], _signingKey, HashAlgorithm.Sha256);

        Assert.NotEmpty(result.Jwt);
        Assert.Empty(result.Disclosures);
    }

    private static void AssertRejected(Dictionary<string, object> claims)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                claims, [], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("_sd_alg", exception.Message);
    }
}
