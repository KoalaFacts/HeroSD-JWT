using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using System.Text.Json;

namespace HeroSdJwt.Tests.Unit.Models;

public class DisclosureWireEncodingTests
{
    [Theory]
    [InlineData("\"Alice\"", "name")]
    [InlineData("{\"greeting\":\"こんにちは 🦘\",\"items\":[1,true,null,\"line\\nbreak\"]}", "display.name")]
    [InlineData("123.4500", "amount")]
    [InlineData("null", "空")]
    public void Should_PreserveExactObjectDisclosureWireBytes(string valueJson, string claimName)
    {
        using var document = JsonDocument.Parse(valueJson);
        var disclosure = new Disclosure("fixed-salt", claimName, document.RootElement);

        var encoded = disclosure.ToBase64Url();

        Assert.Equal(Base64UrlEncoder.Encode(disclosure.ToJson()), encoded);
        Assert.Equal(disclosure.ToJson(), Base64UrlEncoder.DecodeString(encoded));
    }

    [Theory]
    [InlineData("\"text\"")]
    [InlineData("[\"🏡\",{\"items\":[1,2]}]")]
    [InlineData("false")]
    public void Should_PreserveExactArrayDisclosureWireBytes(string valueJson)
    {
        using var document = JsonDocument.Parse(valueJson);
        var disclosure = new Disclosure("fixed-salt", document.RootElement);

        var encoded = disclosure.ToBase64Url();

        Assert.Equal(Base64UrlEncoder.Encode(disclosure.ToJson()), encoded);
        Assert.Equal(disclosure.ToJson(), Base64UrlEncoder.DecodeString(encoded));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectOversizedDisclosureBytesWithoutEncoding(bool multibyte)
    {
        // The prior string-based encoder rejected at 10 MiB of UTF-8.
        // A multibyte string also protects against checking UTF-16 length only.
        var claimText = multibyte ? new string('界', 3_500_000) : new string('a', 10 * 1024 * 1024);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(claimText));
        var generator = new DisclosureGenerator();

        _ = Assert.Throws<ArgumentOutOfRangeException>(() =>
            generator.GenerateDisclosure("oversized", document.RootElement));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() =>
            generator.GenerateArrayElementDisclosure(document.RootElement));
    }

    [Fact]
    public void Should_PreserveGeneratorWireBytesForObjectAndArrayDisclosures()
    {
        using var document = JsonDocument.Parse("""{"quote":"a \"quoted\" value","emoji":"🦘","nested":[null,{"ok":true}]}""");
        var generator = new DisclosureGenerator();
        var objectEncoded = generator.GenerateDisclosure("名前", document.RootElement);
        var arrayEncoded = generator.GenerateArrayElementDisclosure(document.RootElement);

        using var objectDocument = JsonDocument.Parse(Base64UrlEncoder.DecodeString(objectEncoded));
        using var arrayDocument = JsonDocument.Parse(Base64UrlEncoder.DecodeString(arrayEncoded));
        var objectArray = objectDocument.RootElement;
        var array = arrayDocument.RootElement;
        var reconstructedObject = new Disclosure(
            objectArray[0].GetString()!, objectArray[1].GetString()!, objectArray[2]);
        var reconstructedArray = new Disclosure(array[0].GetString()!, array[1]);

        Assert.Equal(3, objectArray.GetArrayLength());
        Assert.Equal(2, array.GetArrayLength());
        Assert.Equal(Base64UrlEncoder.Encode(reconstructedObject.ToJson()), objectEncoded);
        Assert.Equal(Base64UrlEncoder.Encode(reconstructedArray.ToJson()), arrayEncoded);
    }
}
