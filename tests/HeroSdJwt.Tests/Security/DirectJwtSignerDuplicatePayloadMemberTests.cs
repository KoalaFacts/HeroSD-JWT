using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Direct JWT signing must not produce payloads that the JWT verifier rejects
/// because JSON consumers can interpret duplicate names differently.
/// </summary>
public sealed class DirectJwtSignerDuplicatePayloadMemberTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ """{"role":"reader","role":"admin"}""")]
    [InlineData(/*lang=json,strict*/ """{"role":"reader","\u0072ole":"admin"}""")]
    [InlineData(/*lang=json,strict*/ """{"profile":[{"role":"reader","role":"admin"}]}""")]
    public void Should_RejectDuplicateJsonMembersInDirectJwtSigning(string json)
    {
        using var document = JsonDocument.Parse(json);
        var payload = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["profile"] = document.RootElement
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            new JwtSigner().CreateJwt(payload, new byte[32], SignatureAlgorithm.HS256));

        Assert.Equal("value", exception.ParamName);
    }

    [Fact]
    public void Should_AcceptSameNameInIndependentNestedObjects()
    {
        using var document = JsonDocument.Parse(
            /*lang=json,strict*/ """{"primary":{"role":"reader"},"secondary":{"role":"admin"}}""");
        var payload = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["profile"] = document.RootElement
        };
        var signingKey = new byte[32];

        var jwt = new JwtSigner().CreateJwt(payload, signingKey, SignatureAlgorithm.HS256);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, signingKey));
    }
}
