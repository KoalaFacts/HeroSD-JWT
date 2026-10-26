using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using System.Text.Json;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// Issuing a token must never add an implicit expiration to the caller's
/// mutable claims dictionary, including when validation fails.
/// </summary>
public class IssuerImplicitExpirationContractTests
{
    private static readonly byte[] _signingKey = new byte[32];

    [Fact]
    public void Should_SignImplicitExpirationWithoutMutatingCallerClaims()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "subject-123",
            ["email"] = "holder@example.test"
        };
        var issuer = TestHelpers.CreateIssuer();

        var first = issuer.CreateSdJwt(claims, ["email"], _signingKey, HashAlgorithm.Sha256);
        var second = issuer.CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256);

        Assert.Equal(2, claims.Count);
        Assert.False(claims.ContainsKey("exp"));
        Assert.Equal("subject-123", claims["sub"]);
        Assert.Equal("holder@example.test", claims["email"]);

        foreach (var jwt in new[] { first.Jwt, second.Jwt })
        {
            var payload = Base64UrlEncoder.DecodeString(jwt.Split('.')[1]);
            using var document = JsonDocument.Parse(payload);
            Assert.True(document.RootElement.TryGetProperty("exp", out var expiration));
            Assert.True(expiration.TryGetInt64(out var unixTime));
            Assert.True(unixTime > DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        }
    }

    [Fact]
    public void Should_NotInsertImplicitExpirationWhenValidationFails()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "subject-123",
            ["profile"] = new Dictionary<string, object>
            {
                ["_sd_alg"] = "sha-256"
            }
        };
        var issuer = TestHelpers.CreateIssuer();

        _ = Assert.Throws<ArgumentException>(() =>
            issuer.CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256));

        Assert.Equal(2, claims.Count);
        Assert.False(claims.ContainsKey("exp"));
    }

    [Fact]
    public void Should_PreserveExplicitExpirationAndCallerClaims()
    {
        const long explicitExpiration = 4_102_444_800;
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "subject-123",
            ["exp"] = explicitExpiration
        };
        var issuer = TestHelpers.CreateIssuer();

        var issued = issuer.CreateSdJwt(claims, [], _signingKey, HashAlgorithm.Sha256);

        Assert.Equal(2, claims.Count);
        Assert.Equal(explicitExpiration, claims["exp"]);
        var payload = Base64UrlEncoder.DecodeString(issued.Jwt.Split('.')[1]);
        using var document = JsonDocument.Parse(payload);
        Assert.Equal(explicitExpiration, document.RootElement.GetProperty("exp").GetInt64());
    }
}
