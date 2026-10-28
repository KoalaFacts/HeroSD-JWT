using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The issuer must reject ambiguous nested JSON before signing, rather than
/// issuing credentials that the verifier will subsequently reject or that
/// downstream JSON consumers could interpret with different member values.
/// </summary>
public class IssuerNestedJsonMemberAdmissionTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("""{"role":"reader","role":"admin"}""")]
    [InlineData("""{"role":"reader","\u0072ole":"admin"}""")]
    [InlineData("""{"settings":{"active":false,"active":true}}""")]
    [InlineData("""[{"permission":"read","permission":"write"}]""")]
    [InlineData("""{"roles":[{"level":1,"level":2}]}""")]
    public void Should_RejectDuplicateNestedJsonNamesBeforeSigning(string nestedJson)
    {
        using var document = JsonDocument.Parse(nestedJson);
        var claims = new Dictionary<string, object>
        {
            ["profile"] = document.RootElement.Clone()
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256));

        Assert.Contains("duplicate", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Should_AcceptUniqueNestedJsonNamesAndProduceVerifiableCredential()
    {
        using var document = JsonDocument.Parse(
            """{"roles":[{"permission":"read"},{"permission":"write"}],"settings":{"active":true}}""");
        var claims = new Dictionary<string, object>
        {
            ["profile"] = document.RootElement.Clone()
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
