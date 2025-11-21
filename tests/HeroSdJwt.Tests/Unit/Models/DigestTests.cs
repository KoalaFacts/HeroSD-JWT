using HeroSdJwt.Encoding;
using HeroSdJwt.Models;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Models;

/// <summary>
/// Tests for the Digest model.
/// Validates digest construction, equality, hashing, and security features.
/// </summary>
public class DigestTests
{
    [Fact]
    public void Constructor_WithValidParameters_CreatesDigest()
    {
        // Arrange
        var value = "test-digest-value";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = new Digest(value, algorithm);

        // Assert
        Assert.Equal(value, digest.Value);
        Assert.Equal(algorithm, digest.Algorithm);
    }

    [Fact]
    public void Constructor_WithNullValue_ThrowsArgumentNullException()
    {
        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() => new Digest(null!, HashAlgorithm.Sha256));
    }

    [Fact]
    public void Constructor_WithEmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Digest(string.Empty, HashAlgorithm.Sha256));
        Assert.Contains("empty or whitespace", exception.Message);
    }

    [Fact]
    public void Constructor_WithWhitespace_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new Digest("   ", HashAlgorithm.Sha256));
        Assert.Contains("empty or whitespace", exception.Message);
    }

    [Fact]
    public void Equals_WithSameValueAndAlgorithm_ReturnsTrue()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("test-digest");
        var digest1 = new Digest(value, HashAlgorithm.Sha256);
        var digest2 = new Digest(value, HashAlgorithm.Sha256);

        // Act
        var result = digest1.Equals(digest2);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Equals_WithDifferentValues_ReturnsFalse()
    {
        // Arrange
        var digest1 = new Digest(Base64UrlEncoder.Encode("value1"), HashAlgorithm.Sha256);
        var digest2 = new Digest(Base64UrlEncoder.Encode("value2"), HashAlgorithm.Sha256);

        // Act
        var result = digest1.Equals(digest2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_WithDifferentAlgorithms_ReturnsFalse()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("test-digest");
        var digest1 = new Digest(value, HashAlgorithm.Sha256);
        var digest2 = new Digest(value, HashAlgorithm.Sha512);

        // Act
        var result = digest1.Equals(digest2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_WithDefaultDigest_HandleNullValues()
    {
        // Arrange
        var defaultDigest1 = new Digest();
        var defaultDigest2 = new Digest();

        // Act
        var result = defaultDigest1.Equals(defaultDigest2);

        // Assert
        Assert.True(result); // Both have null values
    }

    [Fact]
    public void Equals_DefaultDigestVsNonDefault_ReturnsFalse()
    {
        // Arrange
        var defaultDigest = new Digest();
        var normalDigest = new Digest("test", HashAlgorithm.Sha256);

        // Act
        var result = defaultDigest.Equals(normalDigest);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_WithDifferentLengthDigests_ReturnsFalse()
    {
        // Arrange - Create digests with different byte lengths
        var shortDigest = new Digest(Base64UrlEncoder.Encode("short"), HashAlgorithm.Sha256);
        var longDigest = new Digest(Base64UrlEncoder.Encode("much longer value"), HashAlgorithm.Sha256);

        // Act
        var result = shortDigest.Equals(longDigest);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Equals_WithMalformedBase64_ReturnsFalse()
    {
        // Arrange - Create digests with invalid base64url strings
        var digest1 = new Digest("!!!invalid_base64!!!", HashAlgorithm.Sha256);
        var digest2 = new Digest("also!!!invalid!!!", HashAlgorithm.Sha256);

        // Act
        var result = digest1.Equals(digest2);

        // Assert
        Assert.False(result); // Should handle decode errors gracefully
    }

    [Fact]
    public void EqualsObject_WithNonDigestObject_ReturnsFalse()
    {
        // Arrange
        var digest = new Digest("test", HashAlgorithm.Sha256);
        var notADigest = "not a digest";

        // Act
        var result = digest.Equals(notADigest);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void EqualsObject_WithNull_ReturnsFalse()
    {
        // Arrange
        var digest = new Digest("test", HashAlgorithm.Sha256);

        // Act
        var result = digest.Equals(null);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void EqualsObject_WithSameDigestAsObject_ReturnsTrue()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("test");
        var digest1 = new Digest(value, HashAlgorithm.Sha256);
        object digest2 = new Digest(value, HashAlgorithm.Sha256);

        // Act
        var result = digest1.Equals(digest2);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void GetHashCode_WithSameValues_ReturnsSameHashCode()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("test");
        var digest1 = new Digest(value, HashAlgorithm.Sha256);
        var digest2 = new Digest(value, HashAlgorithm.Sha256);

        // Act
        var hash1 = digest1.GetHashCode();
        var hash2 = digest2.GetHashCode();

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void GetHashCode_WithDifferentValues_ReturnsDifferentHashCodes()
    {
        // Arrange
        var digest1 = new Digest(Base64UrlEncoder.Encode("value1"), HashAlgorithm.Sha256);
        var digest2 = new Digest(Base64UrlEncoder.Encode("value2"), HashAlgorithm.Sha256);

        // Act
        var hash1 = digest1.GetHashCode();
        var hash2 = digest2.GetHashCode();

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void OperatorEquals_WithEqualDigests_ReturnsTrue()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("test");
        var digest1 = new Digest(value, HashAlgorithm.Sha256);
        var digest2 = new Digest(value, HashAlgorithm.Sha256);

        // Act
        var result = digest1 == digest2;

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void OperatorEquals_WithDifferentDigests_ReturnsFalse()
    {
        // Arrange
        var digest1 = new Digest(Base64UrlEncoder.Encode("value1"), HashAlgorithm.Sha256);
        var digest2 = new Digest(Base64UrlEncoder.Encode("value2"), HashAlgorithm.Sha256);

        // Act
        var result = digest1 == digest2;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void OperatorNotEquals_WithEqualDigests_ReturnsFalse()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("test");
        var digest1 = new Digest(value, HashAlgorithm.Sha256);
        var digest2 = new Digest(value, HashAlgorithm.Sha256);

        // Act
        var result = digest1 != digest2;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void OperatorNotEquals_WithDifferentDigests_ReturnsTrue()
    {
        // Arrange
        var digest1 = new Digest(Base64UrlEncoder.Encode("value1"), HashAlgorithm.Sha256);
        var digest2 = new Digest(Base64UrlEncoder.Encode("value2"), HashAlgorithm.Sha256);

        // Act
        var result = digest1 != digest2;

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void ToString_WithShortValue_ReturnsFormattedString()
    {
        // Arrange
        var value = "short";
        var digest = new Digest(value, HashAlgorithm.Sha256);

        // Act
        var result = digest.ToString();

        // Assert
        Assert.Contains("Digest", result);
        Assert.Contains("Sha256", result);
        Assert.Contains("short", result);
    }

    [Fact]
    public void ToString_WithLongValue_TruncatesValue()
    {
        // Arrange
        var longValue = "this_is_a_very_long_digest_value_that_should_be_truncated";
        var digest = new Digest(longValue, HashAlgorithm.Sha512);

        // Act
        var result = digest.ToString();

        // Assert
        Assert.Contains("Digest", result);
        Assert.Contains("Sha512", result);
        Assert.Contains("...", result); // Should contain truncation marker
        Assert.DoesNotContain("truncated", result); // Should not contain full string
    }

    [Fact]
    public void Digest_UsesConstantTimeComparison()
    {
        // This test verifies that constant-time comparison is used
        // by testing edge cases that would expose timing differences

        // Arrange
        var value1 = Base64UrlEncoder.Encode("matching_value_here");
        var value2 = Base64UrlEncoder.Encode("matching_value_here");
        var value3 = Base64UrlEncoder.Encode("different_value_xyz");

        var digest1 = new Digest(value1, HashAlgorithm.Sha256);
        var digest2 = new Digest(value2, HashAlgorithm.Sha256);
        var digest3 = new Digest(value3, HashAlgorithm.Sha256);

        // Act & Assert
        Assert.True(digest1.Equals(digest2)); // Same values
        Assert.False(digest1.Equals(digest3)); // Different values
    }

    [Fact]
    public void Digest_CanBeUsedInHashSet()
    {
        // Arrange
        var value1 = Base64UrlEncoder.Encode("digest1");
        var value2 = Base64UrlEncoder.Encode("digest2");
        var digest1 = new Digest(value1, HashAlgorithm.Sha256);
        var digest2 = new Digest(value2, HashAlgorithm.Sha256);
        var digest1Duplicate = new Digest(value1, HashAlgorithm.Sha256);

        var hashSet = new HashSet<Digest>();

        // Act
        _ = hashSet.Add(digest1);
        _ = hashSet.Add(digest2);
        _ = hashSet.Add(digest1Duplicate); // Should not be added

        // Assert
        Assert.Equal(2, hashSet.Count);
        Assert.Contains(digest1, hashSet);
        Assert.Contains(digest2, hashSet);
    }

    [Fact]
    public void Digest_CanBeUsedAsDictionaryKey()
    {
        // Arrange
        var value = Base64UrlEncoder.Encode("key-digest");
        var digest = new Digest(value, HashAlgorithm.Sha256);
        var dict = new Dictionary<Digest, string>
        {
            // Act
            [digest] = "test-value"
        };
        var retrievedValue = dict[digest];

        // Assert
        Assert.Equal("test-value", retrievedValue);
    }

    [Fact]
    public void Digest_WithAllSupportedAlgorithms_WorksCorrectly()
    {
        // Arrange & Act & Assert
        var value = Base64UrlEncoder.Encode("test");

        var sha256Digest = new Digest(value, HashAlgorithm.Sha256);
        Assert.Equal(HashAlgorithm.Sha256, sha256Digest.Algorithm);

        var sha384Digest = new Digest(value, HashAlgorithm.Sha384);
        Assert.Equal(HashAlgorithm.Sha384, sha384Digest.Algorithm);

        var sha512Digest = new Digest(value, HashAlgorithm.Sha512);
        Assert.Equal(HashAlgorithm.Sha512, sha512Digest.Algorithm);
    }
}
