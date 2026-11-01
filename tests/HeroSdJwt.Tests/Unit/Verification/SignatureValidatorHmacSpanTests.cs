using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Checks that HMAC verification remains interoperable after using the
/// allocation-light span API across every supported HMAC algorithm.
/// </summary>
public sealed class SignatureValidatorHmacSpanTests
{
    [Theory]
    [InlineData(SignatureAlgorithm.HS256, 32)]
    [InlineData(SignatureAlgorithm.HS256, 256)]
    [InlineData(SignatureAlgorithm.HS384, 48)]
    [InlineData(SignatureAlgorithm.HS384, 256)]
    [InlineData(SignatureAlgorithm.HS512, 64)]
    [InlineData(SignatureAlgorithm.HS512, 256)]
    public void Should_ValidateFullLengthHmacAndRejectTampering_WithSupportedKeyLengths(
        SignatureAlgorithm algorithm, int keyLength)
    {
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object>
            {
                ["sub"] = "hmac-span-regression",
                ["exp"] = 4102444800L
            },
            key,
            algorithm);

        var validator = new SignatureValidator();
        Assert.True(validator.VerifyJwtSignature(jwt, key));

        var parts = jwt.Split('.');
        var signature = Base64UrlEncoder.DecodeBytes(parts[2]);
        signature[^1] ^= 1;
        var tamperedJwt = $"{parts[0]}.{parts[1]}.{Base64UrlEncoder.Encode(signature)}";
        Assert.False(validator.VerifyJwtSignature(tamperedJwt, key));

        // A truncated signature is invalid independently of the key size.
        var truncatedJwt = $"{parts[0]}.{parts[1]}.{Base64UrlEncoder.Encode(signature[..^1])}";
        Assert.False(validator.VerifyJwtSignature(truncatedJwt, key));
    }
}
