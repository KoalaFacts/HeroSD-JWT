using HeroSdJwt.Encoding;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A negative decoy count is an invalid privacy policy. The low-level issuer
/// must reject it rather than silently signing a token without requested decoys.
/// </summary>
public class NegativeDecoyCountAdmissionTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(int.MinValue, false)]
    [InlineData(int.MinValue, true)]
    public void Should_RejectNegativeDecoyCount_AtLowLevelIssuer(int decoyCount, bool discloseEmail)
    {
        var selected = discloseEmail ? new[] { "email" } : Array.Empty<string>();
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                new Dictionary<string, object>
                {
                    ["sub"] = "holder-1",
                    ["email"] = "holder@example.test"
                },
                selected,
                _signingKey,
                HashAlgorithm.Sha256,
                decoyDigestCount: decoyCount));

        Assert.Equal("decoyDigestCount", exception.ParamName);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(2, 3)]
    public void Should_PreserveValidDecoyCounts(int decoyCount, int expectedDigests)
    {
        var credential = TestHelpers.CreateIssuer().CreateSdJwt(
            new Dictionary<string, object>
            {
                ["sub"] = "holder-1",
                ["email"] = "holder@example.test"
            },
            ["email"],
            _signingKey,
            HashAlgorithm.Sha256,
            decoyDigestCount: decoyCount);

        Assert.Single(credential.Disclosures);
        var payload = credential.Jwt.Split('.')[1];
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeString(payload));
        Assert.Equal(expectedDigests, document.RootElement.GetProperty("_sd").GetArrayLength());
    }
}
