using HeroSdJwt.Encoding;
using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Models;

public class DigestEqualityContractTests
{
    [Fact]
    public void Should_HashEquivalentDigestBytesEqually_WhenBase64UrlPaddingDiffers()
    {
        // Base64Url.DecodeFromChars accepts both padded and unpadded forms.
        // Both values represent the same 32-byte SHA-256 digest.
        var unpaddedValue = Base64UrlEncoder.Encode(new byte[32]);
        var canonical = new Digest(unpaddedValue, HashAlgorithm.Sha256);
        var padded = new Digest(unpaddedValue + "=", HashAlgorithm.Sha256);

        Assert.True(canonical.Equals(padded));
        Assert.Equal(canonical.GetHashCode(), padded.GetHashCode());
        Assert.Contains(padded, new HashSet<Digest> { canonical });
    }

    [Fact]
    public void Should_CompareSameMalformedValueEqually_WithoutEquatingDistinctMalformedValues()
    {
        // The public constructor currently permits non-base64url values.
        // An IEquatable<T> value must still equal itself and an identical copy.
        var first = new Digest(new string('!', 6), HashAlgorithm.Sha256);
        var same = new Digest(new string('!', 6), HashAlgorithm.Sha256);
        var different = new Digest(new string('?', 6), HashAlgorithm.Sha256);

        Assert.True(first.Equals(first));
        Assert.True(first.Equals(same));
        Assert.Equal(first.GetHashCode(), same.GetHashCode());
        Assert.False(first.Equals(different));
    }
}
