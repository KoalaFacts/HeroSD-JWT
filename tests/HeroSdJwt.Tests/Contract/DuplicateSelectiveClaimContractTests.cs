using HeroSdJwt.Encoding;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Selecting the same claim twice must not create conflicting disclosures
/// or make an otherwise valid credential impossible to issue.
/// </summary>
public class DuplicateSelectiveClaimContractTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Repeat((byte)0x37, 32)];

    [Fact]
    public void Should_IssueOneDisclosure_When_SelectorRepeatedAcrossBuilderCalls()
    {
        var sdJwt = SdJwtIssuerBuilder.Create()
            .WithClaim("sub", "user-123")
            .WithClaim("email", "alice@example.test")
            .MakeSelective("email")
            .MakeSelective("email")
            .SignWithHmac(_signingKey)
            .Build();

        _ = Assert.Single(sdJwt.Disclosures);
        Assert.NotNull(sdJwt.ClaimPathMapping);
        Assert.Equal(0, sdJwt.ClaimPathMapping["email"]);

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();
        var result = verifier.VerifyPresentation(sdJwt.ToPresentation("email"), _signingKey);

        Assert.True(result.IsValid);
        Assert.Equal("alice@example.test", result.DisclosedClaims["email"].GetString());
    }

    [Fact]
    public void Should_IssueEachDistinctDisclosureOnce_When_LowLevelSelectorsRepeat()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["email"] = "alice@example.test",
            ["age"] = 30
        };

        var sdJwt = TestHelpers.CreateIssuer().CreateSdJwt(
            claims,
            ["email", "age", "email", "age"],
            _signingKey,
            HashAlgorithm.Sha256);

        Assert.Equal(2, sdJwt.Disclosures.Count);
        Assert.NotNull(sdJwt.ClaimPathMapping);
        Assert.Equal(2, sdJwt.ClaimPathMapping.Count);

        var jwtParts = sdJwt.Jwt.Split('.');
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(jwtParts[1]));
        Assert.Equal(2, payload.RootElement.GetProperty("_sd").GetArrayLength());
    }
}
