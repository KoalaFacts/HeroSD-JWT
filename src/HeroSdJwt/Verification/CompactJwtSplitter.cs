namespace HeroSdJwt.Verification;

/// <summary>
/// Separates compact JWS segments without an unbounded Split position buffer.
/// Do not allocate any segment strings unless exactly two dots exist.
/// </summary>
internal static class CompactJwtSplitter
{
    internal static string[]? Split(string jwt)
    {
        var first = jwt.IndexOf('.');
        if (first < 0)
        {
            return null;
        }

        var second = jwt.IndexOf('.', first + 1);
        if (second < 0 || jwt.IndexOf('.', second + 1) >= 0)
        {
            return null;
        }

        return [jwt[..first], jwt[(first + 1)..second], jwt[(second + 1)..]];
    }
}
