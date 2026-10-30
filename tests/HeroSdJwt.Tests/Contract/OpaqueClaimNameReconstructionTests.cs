using HeroSdJwt.Extensions;
using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// A valid verification result can include opaque JSON claim names alongside
/// paths supported by the convenience reconstruction extensions.
/// </summary>
public class OpaqueClaimNameReconstructionTests
{
    [Fact]
    public void GetDisclosedArray_Should_IgnoreUnrelatedUriClaimName()
    {
        var result = CreateResult();

        var degrees = result.GetDisclosedArray("degrees");

        _ = Assert.NotNull(degrees);
        Assert.Equal(2, degrees.Value.GetArrayLength());
        Assert.Equal(JsonValueKind.Null, degrees.Value[0].ValueKind);
        Assert.Equal("MBA", degrees.Value[1].GetString());
    }

    [Fact]
    public void GetDisclosedObject_Should_IgnoreUnrelatedUriClaimName()
    {
        var result = CreateResult();

        var address = result.GetDisclosedObject("address");

        _ = Assert.NotNull(address);
        Assert.Equal("Main Street", address.Value.GetProperty("street").GetString());
    }

    [Fact]
    public void GetDisclosedObject_Should_NotTreatDottedUrnAsNestedProperty()
    {
        var result = CreateResult();

        Assert.Null(result.GetDisclosedObject("urn:example:claims"));
    }

    [Fact]
    public void GetReconstructibleClaims_Should_IgnoreUnrelatedUriClaimName()
    {
        var result = CreateResult();

        var claims = result.GetReconstructibleClaims();

        Assert.Equal(2, claims.Count);
        Assert.Equal(ReconstructibleClaimType.Array, claims["degrees"]);
        Assert.Equal(ReconstructibleClaimType.Object, claims["address"]);
    }

    private static VerificationResult CreateResult()
    {
        // JSON claim names may be absolute URIs; they do not imply a path
        // traversal attempt and must not break unrelated reconstruction.
        using var document = JsonDocument.Parse("""
            {
              "https://example.org/claims/employee-id": "employee-42",
              "urn:example:claims.employee-id": "employee-99",
              "degrees[1]": "MBA",
              "address.street": "Main Street"
            }
            """);

        var claims = document.RootElement.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value);

        return new VerificationResult(claims);
    }
}
