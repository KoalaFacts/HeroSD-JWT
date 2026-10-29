using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Models;

public class DisclosureOwnershipTests
{
    [Fact]
    public void ObjectProperty_PreservesClaimValueAfterSourceDocumentIsDisposed()
    {
        Disclosure disclosure;
        using (var document = JsonDocument.Parse("""{"role":"admin","permissions":["read","write"]}"""))
        {
            disclosure = new Disclosure("salt", "profile", document.RootElement);
        }

        Assert.Equal("admin", disclosure.ClaimValue.GetProperty("role").GetString());
        Assert.Equal(2, disclosure.ClaimValue.GetProperty("permissions").GetArrayLength());
        using var encoded = JsonDocument.Parse(disclosure.ToJson());
        Assert.Equal("admin", encoded.RootElement[2].GetProperty("role").GetString());
    }

    [Fact]
    public void ArrayElement_PreservesClaimValueAfterSourceDocumentIsDisposed()
    {
        Disclosure disclosure;
        using (var document = JsonDocument.Parse("""[null,{"level":2}]"""))
        {
            disclosure = new Disclosure("salt", document.RootElement);
        }

        Assert.Equal(JsonValueKind.Null, disclosure.ClaimValue[0].ValueKind);
        Assert.Equal(2, disclosure.ClaimValue[1].GetProperty("level").GetInt32());
        using var encoded = JsonDocument.Parse(disclosure.ToJson());
        Assert.Equal(2, encoded.RootElement[1][1].GetProperty("level").GetInt32());
    }
}
