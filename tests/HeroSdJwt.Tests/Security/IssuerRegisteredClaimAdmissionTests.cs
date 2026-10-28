using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The issuer must not sign registered JWT claims that its own verifier (and
/// RFC 7519 conforming consumers) reject. A successful signature must not
/// disguise an invalid claim representation.
/// </summary>
public class IssuerRegisteredClaimAdmissionTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("iss", "null")]
    [InlineData("iss", "17")]
    [InlineData("iss", "true")]
    [InlineData("iss", "[]")]
    [InlineData("sub", "false")]
    [InlineData("sub", "42")]
    [InlineData("sub", "{}")]
    [InlineData("jti", "null")]
    [InlineData("jti", "123")]
    [InlineData("jti", "[\"id\"]")]
    [InlineData("aud", "null")]
    [InlineData("aud", "10")]
    [InlineData("aud", "true")]
    [InlineData("aud", "{}")]
    [InlineData("aud", "[\"expected\",12]")]
    [InlineData("aud", "[false,\"expected\"]")]
    [InlineData("aud", "[\"expected\",null]")]
    [InlineData("aud", "[\"expected\",{}]")]
    [InlineData("nbf", "null")]
    [InlineData("nbf", "\"1760000000\"")]
    [InlineData("nbf", "true")]
    [InlineData("nbf", "253402300800")]
    [InlineData("iat", "null")]
    [InlineData("iat", "\"1760000000\"")]
    [InlineData("iat", "false")]
    [InlineData("iat", "-62135596801")]
    public void Should_RejectInvalidRegisteredClaimBeforeSigning(string claimName, string json)
    {
        using var document = JsonDocument.Parse(json);
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "holder-1",
            [claimName] = document.RootElement.Clone()
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains(claimName, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Should_AcceptWellFormedRegisteredClaimsAndIssueVerifiableToken()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example",
            ["sub"] = "holder-1",
            ["jti"] = "test-jti-1",
            ["aud"] = new[] { "https://verifier-a.example", "https://verifier-b.example" },
            ["iat"] = now,
            ["nbf"] = now - 30,
            ["exp"] = now + 600
        };

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            claims, [], _signingKey, HashAlgorithm.Sha256);
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var result = verifier.TryVerifyPresentation(sdJwt.Jwt + "~", _signingKey);
        Assert.True(result.IsValid, result.ErrorDetails);
    }
}
