using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The issuer must reject malformed escaped UTF-16 in caller-supplied JSON
/// before signing a credential the verifier would refuse to consume.
/// </summary>
public sealed class IssuerMalformedClaimValueUnicodeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"nickname":"\uD800"}""")]
    [InlineData(/*lang=json,strict*/ """{"roles":[{"description":"\uDC00"}]}""")]
    [InlineData(/*lang=json,strict*/ """["valid","\uD800"]""")]
    public void Should_RejectMalformedNestedStringsBeforeIssuance(string claimJson)
    {
        using var document = JsonDocument.Parse(claimJson);
        var claims = new Dictionary<string, object>
        {
            ["profile"] = document.RootElement.Clone()
        };

        var error = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("Unicode", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Should_PreserveValidEscapedSurrogatePairInIssuedCredential()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"nickname":"\uD83D\uDE00"}""");
        var claims = new Dictionary<string, object>
        {
            ["profile"] = document.RootElement.Clone()
        };

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256);
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var verified = verifier.TryVerifyPresentation(sdJwt.Jwt + "~", _signingKey);
        Assert.True(verified.IsValid, verified.ErrorDetails);
    }
}
