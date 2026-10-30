using HeroSdJwt.Extensions;
using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Reconstruction must never silently overwrite one disclosed claim with another
/// when public verification results contain overlapping path selectors.
/// </summary>
public class ReconstructionPathCollisionTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void GetDisclosedObject_WithAncestorAndDescendantSelectors_RejectsAmbiguousStructure(
        bool descendantFirst,
        bool ancestorIsObject)
    {
        // A parent disclosure can contain either a scalar or an object.
        // Regardless of dictionary order, neither may silently replace a
        // separately disclosed descendant (or throw an InvalidCastException).
        var ancestor = ancestorIsObject
            ? JsonSerializer.SerializeToElement(new { lat = "ancestor value" })
            : JsonSerializer.SerializeToElement("ancestor value");
        var descendant = JsonSerializer.SerializeToElement("descendant value");
        var claims = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        if (descendantFirst)
        {
            claims.Add("address.geo.lat", descendant);
            claims.Add("address.geo", ancestor);
        }
        else
        {
            claims.Add("address.geo", ancestor);
            claims.Add("address.geo.lat", descendant);
        }

        var result = new VerificationResult(claims);

        _ = Assert.Throws<InvalidOperationException>(() =>
            result.GetDisclosedObject("address"));
    }
}
