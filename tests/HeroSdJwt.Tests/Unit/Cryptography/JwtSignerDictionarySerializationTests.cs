using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Collections;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// A claim dictionary must be serialized as a JSON object regardless of its
/// value type. Otherwise a credential may sign an array of Key/Value records
/// where callers and verifiers expect structured JSON claims.
/// </summary>
public class JwtSignerDictionarySerializationTests
{
    private static readonly byte[] _signingKey = new byte[32];

    [Fact]
    public void Should_EncodeTypedDictionaryAsObject_AndPreserveSignature()
    {
        var payload = new Dictionary<string, object>
        {
            ["scores"] = new Dictionary<string, int>
            {
                ["maths"] = 99,
                ["english"] = 95
            }
        };

        var jwt = new JwtSigner().CreateJwt(payload, _signingKey, SignatureAlgorithm.HS256);

        using var document = ReadPayload(jwt);
        var scores = document.RootElement.GetProperty("scores");
        Assert.Equal(JsonValueKind.Object, scores.ValueKind);
        Assert.Equal(99, scores.GetProperty("maths").GetInt32());
        Assert.Equal(95, scores.GetProperty("english").GetInt32());
        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, _signingKey));
    }

    [Fact]
    public void Should_PreserveStringKeyedDictionariesNestedInArrays()
    {
        var payload = new Dictionary<string, object>
        {
            ["records"] = new object[]
            {
                new Dictionary<string, bool> { ["verified"] = true },
                new Hashtable { ["city"] = "Sydney" }
            }
        };

        var jwt = new JwtSigner().CreateJwt(payload, _signingKey, SignatureAlgorithm.HS256);

        using var document = ReadPayload(jwt);
        var records = document.RootElement.GetProperty("records");
        Assert.Equal(JsonValueKind.Array, records.ValueKind);
        Assert.Equal(JsonValueKind.Object, records[0].ValueKind);
        Assert.True(records[0].GetProperty("verified").GetBoolean());
        Assert.Equal(JsonValueKind.Object, records[1].ValueKind);
        Assert.Equal("Sydney", records[1].GetProperty("city").GetString());
    }

    private static JsonDocument ReadPayload(string jwt)
    {
        var firstDot = jwt.IndexOf('.');
        var secondDot = jwt.IndexOf('.', firstDot + 1);
        return JsonDocument.Parse(Base64UrlEncoder.DecodeString(jwt[(firstDot + 1)..secondDot]));
    }
}
