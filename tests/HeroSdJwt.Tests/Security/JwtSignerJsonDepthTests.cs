using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The signer must not emit a JSON payload deeper than the verifier's
/// default 64-level JsonDocument parsing limit.
/// </summary>
public sealed class JwtSignerJsonDepthTests
{
    private static readonly byte[] SigningKey = new byte[32];

    [Theory]
    [InlineData(64)]
    [InlineData(128)]
    public void Should_RejectNestedCollectionBeyondVerifierJsonDepth(int arrayDepth)
    {
        var payload = new Dictionary<string, object>
        {
            ["nested"] = NestArrays(arrayDepth)
        };

        Assert.Throws<InvalidOperationException>(() =>
            new JwtSigner().CreateJwt(payload, SigningKey, SignatureAlgorithm.HS256));
    }

    [Fact]
    public void Should_RejectDeepJsonElementBeyondVerifierJsonDepth()
    {
        var json = new string('[', 64) + "0" + new string(']', 64);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 128 });
        var payload = new Dictionary<string, object>
        {
            ["nested"] = document.RootElement
        };

        Assert.Throws<InvalidOperationException>(() =>
            new JwtSigner().CreateJwt(payload, SigningKey, SignatureAlgorithm.HS256));
    }

    [Fact]
    public void Should_SignAndVerifyNestedCollectionAtVerifierJsonDepthLimit()
    {
        // Payload object contributes the first level, followed by 63 arrays.
        var payload = new Dictionary<string, object>
        {
            ["nested"] = NestArrays(63)
        };

        var jwt = new JwtSigner().CreateJwt(payload, SigningKey, SignatureAlgorithm.HS256);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, SigningKey));
        using var decoded = JsonDocument.Parse(Base64UrlEncoder.DecodeString(jwt.Split('.')[1]));
        Assert.Equal(JsonValueKind.Array, decoded.RootElement.GetProperty("nested").ValueKind);
    }

    private static object NestArrays(int depth)
    {
        object value = "leaf";
        for (var i = 0; i < depth; i++)
        {
            value = new object[] { value };
        }

        return value;
    }
}
