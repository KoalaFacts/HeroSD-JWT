namespace HeroSdJwt.Verification.ReplayProtection;

/// <summary>
/// Represents a composite cache key for jti entries.
/// Combines issuer and jti to prevent cross-issuer collisions per RFC 7519 Section 4.1.7.
/// </summary>
internal readonly struct JtiCacheKey : IEquatable<JtiCacheKey>
{
    public string Issuer { get; init; }
    public string Jti { get; init; }

    public JtiCacheKey(string issuer, string jti)
    {
        Issuer = issuer;
        Jti = jti;
    }

    public override string ToString() => $"{Issuer}:{Jti}";

    public override bool Equals(object? obj) => obj is JtiCacheKey other && Equals(other);

    public bool Equals(JtiCacheKey other) =>
        Issuer == other.Issuer && Jti == other.Jti;

    public override int GetHashCode() => HashCode.Combine(Issuer, Jti);

    public static bool operator ==(JtiCacheKey left, JtiCacheKey right) => left.Equals(right);

    public static bool operator !=(JtiCacheKey left, JtiCacheKey right) => !left.Equals(right);
}
