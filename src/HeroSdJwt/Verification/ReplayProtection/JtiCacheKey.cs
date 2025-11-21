namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// Represents a composite cache key for jti entries.
/// Combines issuer and jti to prevent cross-issuer collisions per RFC 7519 Section 4.1.7.
/// </summary>
internal readonly struct JtiCacheKey(string issuer, string jti) : IEquatable<JtiCacheKey>
{
    public string Issuer { get; init; } = issuer;

    public string Jti { get; init; } = jti;

    public override string ToString()
    {
        return $"{Issuer}:{Jti}";
    }

    public override bool Equals(object? obj)
    {
        return obj is JtiCacheKey other && Equals(other);
    }

    public bool Equals(JtiCacheKey other)
    {
        return Issuer == other.Issuer && Jti == other.Jti;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Issuer, Jti);
    }

    public static bool operator ==(JtiCacheKey left, JtiCacheKey right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(JtiCacheKey left, JtiCacheKey right)
    {
        return !left.Equals(right);
    }
}
