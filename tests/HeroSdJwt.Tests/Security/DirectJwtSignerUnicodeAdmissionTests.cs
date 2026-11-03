using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The direct signing API must never silently replace invalid UTF-16 in
/// signed claim names or values with the Unicode replacement character.
/// </summary>
public sealed class DirectJwtSignerUnicodeAdmissionTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Should_RejectUnpairedSurrogatesInDirectSignerClaimNamesAndValues(bool highSurrogate)
    {
        var invalid = highSurrogate ? "\uD800" : "\uDC00";
        var claims = new Dictionary<string, object>[]
        {
            new() { [invalid] = "value" },
            new() { ["sub"] = invalid },
            new() { ["profile"] = new Dictionary<string, object> { [invalid] = "value" } },
            new() { ["profile"] = new Dictionary<string, object> { ["name"] = invalid } },
            new() { ["profile"] = new Dictionary<string, string> { [invalid] = "value" } },
            new() { ["profile"] = new Dictionary<string, string> { ["name"] = invalid } },
            new() { ["items"] = new[] { "safe", invalid } }
        };

        foreach (var payload in claims)
        {
            var exception = Assert.Throws<ArgumentException>(() =>
                new JwtSigner().CreateJwt(payload, new byte[32], SignatureAlgorithm.HS256));

            Assert.Contains("invalid UTF-16", exception.Message);
        }
    }

    [Fact]
    public void Should_AcceptValidSurrogatePairsInDirectSignerClaimNamesAndValues()
    {
        const string valid = "\uD83E\uDD98";
        var payload = new Dictionary<string, object>
        {
            ["subject"] = valid,
            ["claim_" + valid] = "ok",
            ["nested"] = new Dictionary<string, string> { ["name"] = valid }
        };
        var key = new byte[32];

        var jwt = new JwtSigner().CreateJwt(payload, key, SignatureAlgorithm.HS256);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, key));
    }
}
