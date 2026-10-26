using HeroSdJwt.Encoding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Issuance must accept RFC 7519 NumericDate seconds at the same precision
/// and in the same representable range as the core verifier.
/// </summary>
public class IssuerNumericDateContractTests
{
    private static readonly byte[] _signingKey = new byte[32];

    [Theory]
    [InlineData("4102444800.25")]
    [InlineData("4.10244480025e9")]
    [InlineData("4102444800.00000001")]
    public void Should_IssueAndVerifyFractionalExpirationWithoutChangingCallerValue(string numericDate)
    {
        using var input = JsonDocument.Parse(numericDate);
        var originalExpiration = input.RootElement.Clone();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "subject-123",
            ["exp"] = originalExpiration
        };

        var credential = TestHelpers.CreateIssuer()
            .CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256);

        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeString(credential.Jwt.Split('.')[1]));
        Assert.Equal(input.RootElement.GetDecimal(), payload.RootElement.GetProperty("exp").GetDecimal());
        Assert.Equal(numericDate, ((JsonElement)claims["exp"]).GetRawText());

        var presenter = new SdJwtPresenter();
        var combined = presenter.FormatPresentation(presenter.CreatePresentationWithAllClaims(credential));
        var verified = TestHelpers.CreateVerifier().TryVerifyPresentation(combined, _signingKey);
        Assert.True(verified.IsValid, verified.ErrorDetails);
    }

    [Theory]
    [InlineData("253402300800")]
    [InlineData("-62135596801")]
    [InlineData("1e400")]
    public void Should_RejectNumericDateOutsideVerifierRangeBeforeSigning(string numericDate)
    {
        using var input = JsonDocument.Parse(numericDate);
        var claims = new Dictionary<string, object>
        {
            ["exp"] = input.RootElement.Clone()
        };

        _ = Assert.Throws<ArgumentException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256));
    }
}
