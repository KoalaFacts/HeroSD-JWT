using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7518 Section 3.2 requires a MAC key at least as long as the
/// digest for HS256, HS384, and HS512. A valid HMAC computed with an
/// undersized secret must not authenticate a JWT.
/// </summary>
public class HmacKeyStrengthAdmissionTests
{
    [Theory]
    [InlineData(SignatureAlgorithm.HS256, 1)]
    [InlineData(SignatureAlgorithm.HS256, 31)]
    [InlineData(SignatureAlgorithm.HS384, 32)]
    [InlineData(SignatureAlgorithm.HS384, 47)]
    [InlineData(SignatureAlgorithm.HS512, 32)]
    [InlineData(SignatureAlgorithm.HS512, 63)]
    public void Should_RefuseToIssueJwtWithUndersizedHmacKey(SignatureAlgorithm algorithm, int keyLength)
    {
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var exception = Assert.Throws<ArgumentException>(() =>
            new JwtSigner().CreateJwt(
                new Dictionary<string, object> { ["exp"] = 4102444800L },
                key,
                algorithm));

        Assert.Equal("signingKey", exception.ParamName);
    }

    [Theory]
    [InlineData("HS256", 1)]
    [InlineData("HS256", 31)]
    [InlineData("HS384", 32)]
    [InlineData("HS384", 47)]
    [InlineData("HS512", 32)]
    [InlineData("HS512", 63)]
    public async Task Should_RejectAuthenticHmacWithUndersizedVerificationKey(string algorithm, int keyLength)
    {
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = algorithm, kid = "short-hmac-key" }));
        var payload = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"exp":4102444800,"sub":"valid-subject"}""");
        var signingInput = header + "." + payload;
        var bytes = System.Text.Encoding.ASCII.GetBytes(signingInput);
        var signature = algorithm switch
        {
            "HS256" => HMACSHA256.HashData(key, bytes),
            "HS384" => HMACSHA384.HashData(key, bytes),
            "HS512" => HMACSHA512.HashData(key, bytes),
            _ => throw new InvalidOperationException("Unsupported test algorithm")
        };
        var jwt = signingInput + "." + Base64UrlEncoder.Encode(signature);
        var presentation = jwt + "~";

        // The BCL generated the cryptographically correct MAC. Verification
        // must still enforce RFC 7518's minimum key length.
        Assert.False(new SignatureValidator().VerifyJwtSignature(jwt, key));

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
        var direct = verifier.TryVerifyPresentation(presentation, key);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, direct.Errors);

        byte[]? Resolve(string kid) => kid == "short-hmac-key" ? key : null;
        var resolved = verifier.TryVerifyPresentation(presentation, Resolve);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, Resolve, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, asyncResolved.Errors);
    }

    [Theory]
    [InlineData(SignatureAlgorithm.HS256, 32)]
    [InlineData(SignatureAlgorithm.HS256, 33)]
    [InlineData(SignatureAlgorithm.HS384, 48)]
    [InlineData(SignatureAlgorithm.HS384, 49)]
    [InlineData(SignatureAlgorithm.HS512, 64)]
    [InlineData(SignatureAlgorithm.HS512, 65)]
    public void Should_KeepIssuingAndVerifyingHmacAtOrAboveRequiredKeyLength(
        SignatureAlgorithm algorithm, int keyLength)
    {
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["exp"] = 4102444800L, ["sub"] = "valid-subject" },
            key,
            algorithm);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, key));

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
        var result = verifier.TryVerifyPresentation(jwt + "~", key);
        Assert.True(result.IsValid, result.ErrorDetails);
    }
}
