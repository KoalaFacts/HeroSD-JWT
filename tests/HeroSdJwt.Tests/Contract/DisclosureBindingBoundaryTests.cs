using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Contract;

public class DisclosureBindingBoundaryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectUnboundDisclosure_When_SignedPayloadHasNoDigests(bool emptyDigestArray)
    {
        var claims = new Dictionary<string, object>();
        if (emptyDigestArray)
        {
            claims["_sd"] = Array.Empty<string>();
        }
        var disclosure = Base64UrlEncoder.Encode("[\"salt\",\"email\",\"unbound@example.com\"]");
        var result = Verify(claims, disclosure);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.DigestMismatch, result.Errors);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_ValidateArrayDisclosureAgainstSignedPlaceholder(bool tampered)
    {
        var original = Base64UrlEncoder.Encode("[\"salt\",\"original\"]");
        var presented = tampered ? Base64UrlEncoder.Encode("[\"salt\",\"changed\"]") : original;
        var digest = new DigestCalculator().ComputeDigest(original, HashAlgorithm.Sha256);
        var claims = new Dictionary<string, object>
        {
            ["items"] = new object[] { new Dictionary<string, object> { ["..."] = digest } }
        };
        var result = Verify(claims, presented);
        Assert.Equal(!tampered, result.IsValid);
        if (tampered)
        {
            Assert.Contains(ErrorCode.DigestMismatch, result.Errors);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Should_ValidateMixedAndNestedArrayDisclosure(bool nested, bool tampered)
    {
        var original = Base64UrlEncoder.Encode("[\"salt\",\"original\"]");
        var presented = tampered ? Base64UrlEncoder.Encode("[\"salt\",\"changed\"]") : original;
        var calculator = new DigestCalculator();
        var items = new object[] { new Dictionary<string, object> { ["..."] = calculator.ComputeDigest(original, HashAlgorithm.Sha256) } };
        var parent = Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(new object[]
        {
            "salt", "profile", nested ? new Dictionary<string, object> { ["items"] = items } : "bound"
        }));
        var claims = new Dictionary<string, object>
        {
            ["_sd"] = new[] { calculator.ComputeDigest(parent, HashAlgorithm.Sha256) }
        };
        if (!nested)
        {
            claims["items"] = items;
        }
        var result = Verify(claims, parent, presented);
        Assert.Equal(!tampered, result.IsValid);
        if (tampered)
        {
            Assert.Contains(ErrorCode.DigestMismatch, result.Errors);
        }
    }

    [Fact]
    public void Should_AcceptNoDisclosures_When_SignedPayloadHasNoDigests()
    {
        Assert.True(Verify([]).IsValid);
    }

    private static VerificationResult Verify(Dictionary<string, object> claims, params string[] disclosures)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        claims["exp"] = 4102444800L;
        var jwt = new JwtSigner().CreateJwt(claims, key, SignatureAlgorithm.HS256);
        var presentation = jwt + "~" + (disclosures.Length == 0 ? "" : string.Join("~", disclosures) + "~");
        return SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build().TryVerifyPresentation(presentation, key);
    }
}
