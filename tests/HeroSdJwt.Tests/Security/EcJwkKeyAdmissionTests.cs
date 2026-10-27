using HeroSdJwt.Cryptography;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// EC public key conversion must not silently normalize ambiguous JSON JWKs
/// or ASN.1 public keys with trailing untrusted data.
/// </summary>
public class EcJwkKeyAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(48)]
    [InlineData(255)]
    public void ToJwk_ShouldRejectTrailingDataAfterValidSpki(int suffix)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = ecdsa.ExportSubjectPublicKeyInfo();
        byte[] trailingSpki = [.. spki, (byte)suffix];
        var converter = new EcPublicKeyConverter();

        // Control: the original, exact SPKI remains supported.
        Assert.Equal("EC", converter.ToJwk(spki)["kty"]);
        Assert.Throws<ArgumentException>(() => converter.ToJwk(trailingSpki));
    }

    [Theory]
    [InlineData("kty", "EC")]
    [InlineData("crv", "P-256")]
    [InlineData("x", "ignored")]
    [InlineData("y", "ignored")]
    public void FromJwk_ShouldRejectDuplicateJwkMembers(string member, string value)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var converter = new EcPublicKeyConverter();
        var jwk = JsonSerializer.Serialize(converter.ToJwk(ecdsa.ExportSubjectPublicKeyInfo()));
        var duplicated = jwk[..^1] + ",\"" + member + "\":\"" + value + "\"}";
        using var document = JsonDocument.Parse(duplicated);

        Assert.Throws<ArgumentException>(() => converter.FromJwk(document.RootElement));
        Assert.Throws<ArgumentException>(() => converter.FromJwkObject(document.RootElement));
    }

    [Fact]
    public void FromJwk_ShouldRejectDuplicateWithEscapedPropertyName()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var converter = new EcPublicKeyConverter();
        var jwk = JsonSerializer.Serialize(converter.ToJwk(ecdsa.ExportSubjectPublicKeyInfo()));
        var duplicated = jwk[..^1] + ",\"\\u006bty\":\"EC\"}";
        using var document = JsonDocument.Parse(duplicated);

        Assert.Throws<ArgumentException>(() => converter.FromJwk(document.RootElement));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("\"not-a-key\"")]
    public void FromJwk_ShouldReportNonObjectAsInvalidArgument(string json)
    {
        using var document = JsonDocument.Parse(json);
        var converter = new EcPublicKeyConverter();

        Assert.Throws<ArgumentException>(() => converter.FromJwk(document.RootElement));
    }

    [Theory]
    [InlineData("kty", "true")]
    [InlineData("kty", "null")]
    [InlineData("kty", "[]")]
    [InlineData("crv", "42")]
    [InlineData("crv", "null")]
    [InlineData("crv", "{}")]
    public void FromJwk_ShouldReportMalformedRegisteredValuesAsInvalidArgument(string field, string value)
    {
        var json = field == "kty"
            ? "{\"kty\":" + value + ",\"crv\":\"P-256\"}"
            : "{\"kty\":\"EC\",\"crv\":" + value + "}";
        using var document = JsonDocument.Parse(json);
        var converter = new EcPublicKeyConverter();

        Assert.Throws<ArgumentException>(() => converter.FromJwk(document.RootElement));
    }
}
