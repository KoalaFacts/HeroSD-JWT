using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A default JsonElement is Undefined and cannot be serialized as a JSON claim.
/// Reject it at the public Disclosure boundary rather than producing an
/// unusable disclosure or failing later during presentation serialization.
/// </summary>
public class UndefinedDisclosureClaimAdmissionTests
{
    [Fact]
    public void Should_RejectUndefinedClaimValue_InObjectPropertyDisclosure()
    {
        var claimValue = default(JsonElement);

        var error = Assert.Throws<ArgumentException>(() =>
            new Disclosure("salt", "profile", claimValue));

        Assert.Equal("claimValue", error.ParamName);
    }

    [Fact]
    public void Should_RejectUndefinedClaimValue_InArrayElementDisclosure()
    {
        var claimValue = default(JsonElement);

        var error = Assert.Throws<ArgumentException>(() =>
            new Disclosure("salt", claimValue));

        Assert.Equal("claimValue", error.ParamName);
    }
}
