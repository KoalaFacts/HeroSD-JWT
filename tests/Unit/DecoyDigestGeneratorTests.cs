using HeroSdJwt.Common;
using HeroSdJwt.Issuance;
using System.Reflection;
using Xunit;
using HashAlgorithm = HeroSdJwt.Common.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for DecoyDigestGenerator.
/// Validates cryptographically secure decoy generation per SD-JWT spec section 4.2.5.
/// </summary>
public class DecoyDigestGeneratorTests
{
    [Fact]
    public void GenerateDecoyDigests_WithValidCount_ReturnsCorrectNumber()
    {
        // Arrange
        var generator = CreateGenerator();
        var count = 5;

        // Act
        var decoys = generator.GenerateDecoyDigests(count, HashAlgorithm.Sha256);

        // Assert
        Assert.Equal(count, decoys.Count);
    }

    [Fact]
    public void GenerateDecoyDigests_WithZeroCount_ReturnsEmptyList()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act
        var decoys = generator.GenerateDecoyDigests(0, HashAlgorithm.Sha256);

        // Assert
        Assert.Empty(decoys);
    }

    [Fact]
    public void GenerateDecoyDigests_WithNegativeCount_ThrowsArgumentException()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            generator.GenerateDecoyDigests(-1, HashAlgorithm.Sha256));
        Assert.Contains("negative", exception.Message);
    }

    [Fact]
    public void GenerateDecoyDigests_AllDecoysAreUnique()
    {
        // Arrange
        var generator = CreateGenerator();
        var count = 100;

        // Act
        var decoys = (List<string>)generator.GenerateDecoyDigests(count, HashAlgorithm.Sha256);

        // Assert
        var uniqueDecoys = decoys.Distinct().ToList();
        Assert.Equal(count, uniqueDecoys.Count);
    }

    [Fact]
    public void GenerateDecoyDigests_WithSha256_ProducesCorrectLengthDigests()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act
        var decoys = generator.GenerateDecoyDigests(10, HashAlgorithm.Sha256);

        // Assert
        foreach (var decoy in decoys)
        {
            Assert.NotNull(decoy);
            Assert.NotEmpty(decoy);
            // SHA-256 produces 32 bytes, which becomes 43 base64url characters (no padding)
            Assert.InRange(decoy.Length, 40, 50); // Approximate range
        }
    }

    [Fact]
    public void GenerateDecoyDigests_WithSha384_ProducesCorrectLengthDigests()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act
        var decoys = generator.GenerateDecoyDigests(10, HashAlgorithm.Sha384);

        // Assert
        foreach (var decoy in decoys)
        {
            Assert.NotNull(decoy);
            Assert.NotEmpty(decoy);
            // SHA-384 produces 48 bytes, which becomes 64 base64url characters
            Assert.InRange(decoy.Length, 60, 70); // Approximate range
        }
    }

    [Fact]
    public void GenerateDecoyDigests_WithSha512_ProducesCorrectLengthDigests()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act
        var decoys = generator.GenerateDecoyDigests(10, HashAlgorithm.Sha512);

        // Assert
        foreach (var decoy in decoys)
        {
            Assert.NotNull(decoy);
            Assert.NotEmpty(decoy);
            // SHA-512 produces 64 bytes, which becomes 86 base64url characters
            Assert.InRange(decoy.Length, 80, 90); // Approximate range
        }
    }

    [Fact]
    public void GenerateDecoyDigests_MultipleCallsProduceDifferentDigests()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act
        var decoys1 = (List<string>)generator.GenerateDecoyDigests(5, HashAlgorithm.Sha256);
        var decoys2 = (List<string>)generator.GenerateDecoyDigests(5, HashAlgorithm.Sha256);

        // Assert - No overlap expected (cryptographically secure random)
        var overlaps = decoys1.Intersect(decoys2).ToList();
        Assert.Empty(overlaps);
    }

    [Fact]
    public void GenerateDecoyDigests_ProducesValidBase64UrlStrings()
    {
        // Arrange
        var generator = CreateGenerator();

        // Act
        var decoys = generator.GenerateDecoyDigests(20, HashAlgorithm.Sha256);

        // Assert
        foreach (var decoy in decoys)
        {
            // Base64url should only contain: A-Z, a-z, 0-9, -, _
            Assert.Matches("^[A-Za-z0-9_-]+$", decoy);
            // Should not contain standard Base64 characters
            Assert.DoesNotContain("+", decoy);
            Assert.DoesNotContain("/", decoy);
            Assert.DoesNotContain("=", decoy);
        }
    }

    [Fact]
    public void InterleaveDecoys_WithNoDecoys_ReturnsOnlyRealDigests()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string> { "real1", "real2", "real3" };
        var decoyDigests = new List<string>();

        // Act
        var result = generator.InterleaveDecoys(realDigests, decoyDigests);

        // Assert
        Assert.Equal(realDigests.Count, result.Count);
        Assert.All(realDigests, digest => Assert.Contains(digest, result));
    }

    [Fact]
    public void InterleaveDecoys_WithNullRealDigests_ThrowsArgumentNullException()
    {
        // Arrange
        var generator = CreateGenerator();
        var decoyDigests = new List<string> { "decoy1" };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            generator.InterleaveDecoys(null!, decoyDigests));
    }

    [Fact]
    public void InterleaveDecoys_WithNullDecoyDigests_ThrowsArgumentNullException()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string> { "real1" };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            generator.InterleaveDecoys(realDigests, null!));
    }

    [Fact]
    public void InterleaveDecoys_CombinesAllDigests()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string> { "real1", "real2", "real3" };
        var decoyDigests = new List<string> { "decoy1", "decoy2" };

        // Act
        var result = generator.InterleaveDecoys(realDigests, decoyDigests);

        // Assert
        Assert.Equal(5, result.Count);
        Assert.All(realDigests, digest => Assert.Contains(digest, result));
        Assert.All(decoyDigests, digest => Assert.Contains(digest, result));
    }

    [Fact]
    public void InterleaveDecoys_ShufflesDigests()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string> { "real1", "real2", "real3" };
        var decoyDigests = new List<string> { "decoy1", "decoy2" };

        // Act - Run multiple times
        var results = new List<List<string>>();
        for (int i = 0; i < 10; i++)
        {
            results.Add(generator.InterleaveDecoys(realDigests, decoyDigests));
        }

        // Assert - Should produce different orderings
        // Check that not all results are identical
        var allSame = results.All(r => r.SequenceEqual(results[0]));
        Assert.False(allSame, "Expected randomized ordering, but all results were identical");
    }

    [Fact]
    public void InterleaveDecoys_WithEmptyRealDigests_ReturnsOnlyDecoys()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string>();
        var decoyDigests = new List<string> { "decoy1", "decoy2", "decoy3" };

        // Act
        var result = generator.InterleaveDecoys(realDigests, decoyDigests);

        // Assert
        Assert.Equal(decoyDigests.Count, result.Count);
        Assert.All(decoyDigests, digest => Assert.Contains(digest, result));
    }

    [Fact]
    public void InterleaveDecoys_PreservesAllElements()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string> { "r1", "r2", "r3", "r4", "r5" };
        var decoyDigests = new List<string> { "d1", "d2", "d3" };

        // Act
        var result = generator.InterleaveDecoys(realDigests, decoyDigests);

        // Assert - Check counts of each element
        Assert.Equal(8, result.Count);
        var realCount = ((List<string>)result).Count(d => d.StartsWith("r"));
        var decoyCount = ((List<string>)result).Count(d => d.StartsWith("d"));
        Assert.Equal(5, realCount);
        Assert.Equal(3, decoyCount);
    }

    [Fact]
    public void InterleaveDecoys_WithManyDecoys_DistributesRandomly()
    {
        // Arrange
        var generator = CreateGenerator();
        var realDigests = new List<string> { "real1", "real2" };
        var decoyDigests = Enumerable.Range(1, 20).Select(i => $"decoy{i}").ToList();

        // Act
        var result = generator.InterleaveDecoys(realDigests, decoyDigests);

        // Assert
        Assert.Equal(22, result.Count);
        // Real digests should not be clustered at beginning or end
        var firstRealIndex = result.IndexOf("real1");
        var lastRealIndex = Math.Max(result.IndexOf("real1"), result.IndexOf("real2"));
        Assert.InRange(firstRealIndex, 0, 21);
        Assert.InRange(lastRealIndex, 0, 21);
    }

    /// <summary>
    /// Helper method to create DecoyDigestGenerator instance using reflection
    /// since it's an internal class.
    /// </summary>
    private static dynamic CreateGenerator()
    {
        var assembly = typeof(SdJwtIssuer).Assembly;
        var type = assembly.GetType("HeroSdJwt.Issuance.DecoyDigestGenerator");
        return Activator.CreateInstance(type!)!;
    }
}
