using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Direct JwtSigner callers must not mint key IDs that verification and
/// revocation subsequently reject. Null and whitespace omission are covered
/// by the existing direct-signer API contract tests.
/// </summary>
public class DirectJwtSignerKeyIdAdmissionTests
{
    private static readonly byte[] _signingKey = new byte[32];

    [Theory]
    [InlineData("key\ninjection")]
    [InlineData("key\u007Fdel")]
    [InlineData("key-\u00E9")]
    public void Should_RejectDisallowedKeyId_WhenSigningDirectly(string keyId)
    {
        var claims = new Dictionary<string, object> { ["sub"] = "holder-1" };

        var exception = Assert.Throws<ArgumentException>(() =>
            new JwtSigner().CreateJwt(claims, _signingKey, SignatureAlgorithm.HS256, keyId));

        Assert.Equal("keyId", exception.ParamName);
    }

    [Fact]
    public void Should_RejectOversizedKeyId_WhenSigningDirectly()
    {
        var claims = new Dictionary<string, object> { ["sub"] = "holder-1" };

        var exception = Assert.Throws<ArgumentException>(() =>
            new JwtSigner().CreateJwt(claims, _signingKey, SignatureAlgorithm.HS256, new string('k', 257)));

        Assert.Equal("keyId", exception.ParamName);
    }

    [Fact]
    public void Should_PreserveMaxLengthPrintableKeyId_WhenSigningDirectly()
    {
        var keyId = new string('k', 256);
        var claims = new Dictionary<string, object> { ["sub"] = "holder-1" };

        var jwt = new JwtSigner().CreateJwt(claims, _signingKey, SignatureAlgorithm.HS256, keyId);
        using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeString(jwt.Split('.')[0]));

        Assert.Equal(keyId, header.RootElement.GetProperty("kid").GetString());
    }
}
