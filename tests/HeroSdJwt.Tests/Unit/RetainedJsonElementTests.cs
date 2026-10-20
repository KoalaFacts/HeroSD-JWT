using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

public class RetainedJsonElementTests
{
    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("1.2300e+02")]
    [InlineData("\"escaped\\u0061\\n\"")]
    [InlineData("{\"nested\":[null,1.2300e+02,{\"x\":true}]}")]
    [InlineData("[null,{\"nested\":[false,\"value\"]}]")]
    public void Should_PreserveNullOwnershipAndSignedJson_When_RetainingArrayValue(string json)
    {
        var signer = new CapturingSigner();
        var issuer = CreateIssuer(signer);
        using (var source = JsonDocument.Parse($"[{json},\"hidden\"]"))
        {
            _ = issuer.CreateSdJwt(new Dictionary<string, object>
            {
                ["items"] = source.RootElement,
                ["exp"] = 4102444800L
            }, ["items[1]"], new byte[32], HashAlgorithm.Sha256);
        }

        var items = Assert.IsType<List<object>>(signer.Payload!["items"]);
        AssertRetainedValue(json, items[0]);
        AssertSignedValue(signer, json, "items", isArray: true);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("false")]
    [InlineData("1.2300e+02")]
    [InlineData("\"escaped\\u0061\\n\"")]
    [InlineData("{\"nested\":[null,1.2300e+02,{\"x\":true}]}")]
    [InlineData("[null,{\"nested\":[false,\"value\"]}]")]
    public void Should_PreserveNullOwnershipAndSignedJson_When_RetainingNestedValue(string json)
    {
        var signer = new CapturingSigner();
        var issuer = CreateIssuer(signer);
        using (var source = JsonDocument.Parse($"{{\"retained\":{json},\"hidden\":\"secret\"}}"))
        {
            _ = issuer.CreateSdJwt(new Dictionary<string, object>
            {
                ["profile"] = source.RootElement,
                ["exp"] = 4102444800L
            }, ["profile.hidden"], new byte[32], HashAlgorithm.Sha256);
        }

        var profile = Assert.IsType<Dictionary<string, object>>(signer.Payload!["profile"]);
        AssertRetainedValue(json, profile["retained"]);
        AssertSignedValue(signer, json, "profile", isArray: false);
    }

    private static SdJwtIssuer CreateIssuer(IJwtSigner signer) =>
        new(new DisclosureGenerator(), new DigestCalculator(), new EcPublicKeyConverter(), signer);

    private static void AssertRetainedValue(string json, object? value)
    {
        if (json == "null")
        {
            Assert.Null(value);
        }
        else
        {
            var element = Assert.IsType<JsonElement>(value);
            // The source document is disposed before this assertion.
            using var expected = JsonDocument.Parse(json);
            Assert.Equal(JsonSerializer.Serialize(expected.RootElement), element.GetRawText());
        }
    }

    private static void AssertSignedValue(CapturingSigner signer, string json, string claim, bool isArray)
    {
        // Sign again after disposal and compare the complete JWT, including signature.
        var jwtAfterDisposal = new JwtSigner().CreateJwt(signer.Payload!, new byte[32], SignatureAlgorithm.HS256);
        Assert.Equal(signer.Jwt, jwtAfterDisposal);

        // Compare with the previous roundtrip representation, keeping salts/digests identical.
        var legacyPayload = new Dictionary<string, object>(signer.Payload!);
        var legacyValue = JsonSerializer.Deserialize<object>(json);
        if (isArray)
        {
            var legacyArray = new List<object>((List<object>)legacyPayload[claim])
            {
                [0] = legacyValue!
            };
            legacyPayload[claim] = legacyArray;
        }
        else
        {
            var legacyObject = new Dictionary<string, object>((Dictionary<string, object>)legacyPayload[claim])
            {
                ["retained"] = legacyValue!
            };
            legacyPayload[claim] = legacyObject;
        }
        Assert.Equal(signer.Jwt, new JwtSigner().CreateJwt(legacyPayload, new byte[32], SignatureAlgorithm.HS256));

        using var payload = JsonDocument.Parse(HeroSdJwt.Encoding.Base64UrlEncoder.DecodeString(jwtAfterDisposal.Split('.')[1]));
        var retained = isArray ? payload.RootElement.GetProperty(claim)[0] : payload.RootElement.GetProperty(claim).GetProperty("retained");
        using var expected = JsonDocument.Parse(json);
        // Both paths use JsonElement.WriteTo, including its escaping normalization.
        Assert.Equal(JsonSerializer.Serialize(expected.RootElement), retained.GetRawText());
    }

    private sealed class CapturingSigner : IJwtSigner
    {
        public Dictionary<string, object>? Payload { get; private set; }
        public string? Jwt { get; private set; }

        public string CreateJwt(Dictionary<string, object> payload, byte[] signingKey, SignatureAlgorithm algorithm, string? keyId = null)
        {
            Payload = payload;
            Jwt = new JwtSigner().CreateJwt(payload, signingKey, algorithm, keyId);
            return Jwt;
        }
    }
}
