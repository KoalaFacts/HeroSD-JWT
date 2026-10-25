using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Exceptions;
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

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Should_RejectInvalidArrayPlaceholderBinding(bool nested, bool objectDisclosure)
    {
        var disclosure = Base64UrlEncoder.Encode(objectDisclosure ? "[\"salt\",\"role\",\"admin\"]" : "[\"salt\",\"admin\"]");
        var calculator = new DigestCalculator();
        var placeholder = new Dictionary<string, object> { ["..."] = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha256) };
        if (!objectDisclosure)
        {
            placeholder["kind"] = "ordinary";
        }
        var claims = new Dictionary<string, object> { ["items"] = new[] { placeholder } };
        string[] disclosures = [disclosure];
        if (nested)
        {
            var parent = Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(new object[] { "salt", "profile", claims }));
            claims = new Dictionary<string, object> { ["_sd"] = new[] { calculator.ComputeDigest(parent, HashAlgorithm.Sha256) } };
            disclosures = [parent, disclosure];
        }
        Assert.False(Verify(claims, disclosures).IsValid);
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("", true)]
    [InlineData(" ", false)]
    [InlineData(" ", true)]
    public async Task Should_ReturnValidationFailure_ForMalformedArrayDigest(string digest, bool invalidSignature)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var claims = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["items"] = new[] { new Dictionary<string, object> { ["..."] = digest } }
        };
        var presentation = new JwtSigner().CreateJwt(claims, key, SignatureAlgorithm.HS256) + "~";
        var verificationKey = invalidSignature ? RandomNumberGenerator.GetBytes(32) : key;
        var verifier = SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();
        Assert.Throws<SdJwtException>(() => verifier.VerifyPresentation(presentation, verificationKey));
        var result = await verifier.VerifyPresentationAsync(presentation, verificationKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(result.IsValid);
        Assert.Contains(invalidSignature ? ErrorCode.InvalidSignature : ErrorCode.InvalidInput, result.Errors);
        if (invalidSignature)
        {
            Assert.Single(result.Errors);
        }
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[\"salt\"]")]
    [InlineData("\"value\"")]
    [InlineData("{invalid")]
    public void Should_RejectArrayDisclosureWithoutTwoElements(string json)
    {
        var disclosure = Base64UrlEncoder.Encode(json);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var claims = new Dictionary<string, object>
        {
            ["items"] = new[] { new Dictionary<string, object> { ["..."] = digest } }
        };
        Assert.False(Verify(claims, disclosure).IsValid);
    }

    [Fact]
    public void Should_AcceptNoDisclosures_When_SignedPayloadHasNoDigests()
    {
        Assert.True(Verify([]).IsValid);
    }


    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectSignedDisclosureThatCollidesWithPermanentClaim(bool nested)
    {
        var disclosure = Base64UrlEncoder.Encode("[\"salt\",\"role\",\"admin\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var collidingObject = new Dictionary<string, object>
        {
            ["role"] = "member",
            ["_sd"] = new[] { digest }
        };
        var payload = nested
            ? new Dictionary<string, object> { ["profile"] = collidingObject }
            : collidingObject;

        var result = Verify(payload, disclosure);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.MalformedDisclosure, result.Errors);
    }

    [Theory]
    [InlineData("_sd")]
    [InlineData("...")]
    public void Should_RejectSignedDisclosureWithReservedClaimName(string name)
    {
        var disclosure = Base64UrlEncoder.Encode($@"[""salt"",""{name}"",""value""]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var result = Verify(new Dictionary<string, object> { ["_sd"] = new[] { digest } }, disclosure);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.MalformedDisclosure, result.Errors);
    }

    [Fact]
    public void Should_AcceptDistinctSelectiveAndPermanentlyDisclosedClaims()
    {
        var disclosure = Base64UrlEncoder.Encode("[\"salt\",\"email\",\"alice@example.test\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var result = Verify(new Dictionary<string, object>
        {
            ["role"] = "member",
            ["_sd"] = new[] { digest }
        }, disclosure);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal("alice@example.test", result.DisclosedClaims["email"].GetString());
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
