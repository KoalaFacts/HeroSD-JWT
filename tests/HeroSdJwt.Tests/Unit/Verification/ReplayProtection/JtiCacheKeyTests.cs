using HeroSdJwt.Verification.ReplayProtection;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

/// <summary>
/// Tests for the internal <see cref="JtiCacheKey"/> composite key.
/// The key combines issuer + jti to prevent cross-issuer jti collisions, so correct
/// equality/hashing semantics are security-relevant (a faulty Equals could let a replayed
/// jti from issuer A be treated as a different jti from issuer B, or vice versa).
/// </summary>
public class JtiCacheKeyTests
{
    [Fact]
    public void ToString_CombinesIssuerAndJti()
    {
        var key = new JtiCacheKey("https://issuer.example.com", "jti-123");

        Assert.Equal("https://issuer.example.com:jti-123", key.ToString());
    }

    [Fact]
    public void Equals_WithSameIssuerAndJti_AreEqual()
    {
        var a = new JtiCacheKey("issuer", "jti");
        var b = new JtiCacheKey("issuer", "jti");

        Assert.True(a.Equals(b));
        Assert.True(a.Equals((object)b));
        Assert.True(a == b);
        Assert.False(a != b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Equals_WithDifferentJti_AreNotEqual()
    {
        var a = new JtiCacheKey("issuer", "jti-1");
        var b = new JtiCacheKey("issuer", "jti-2");

        Assert.False(a.Equals(b));
        Assert.False(a == b);
        Assert.True(a != b);
    }

    [Fact]
    public void Equals_WithDifferentIssuer_AreNotEqual()
    {
        // Same jti, different issuer must NOT collide (cross-issuer protection).
        var a = new JtiCacheKey("issuer-A", "shared-jti");
        var b = new JtiCacheKey("issuer-B", "shared-jti");

        Assert.False(a.Equals(b));
        Assert.True(a != b);
    }

    [Fact]
    public void Equals_WithNonKeyObject_ReturnsFalse()
    {
        var key = new JtiCacheKey("issuer", "jti");

        Assert.False(key.Equals("issuer:jti"));
        Assert.False(key.Equals(null));
    }

    [Fact]
    public void CanBeUsedAsDictionaryKey()
    {
        var dict = new Dictionary<JtiCacheKey, int>
        {
            [new JtiCacheKey("issuer", "jti-1")] = 1
        };

        Assert.True(dict.ContainsKey(new JtiCacheKey("issuer", "jti-1")));
        Assert.False(dict.ContainsKey(new JtiCacheKey("issuer", "jti-2")));
    }
}
