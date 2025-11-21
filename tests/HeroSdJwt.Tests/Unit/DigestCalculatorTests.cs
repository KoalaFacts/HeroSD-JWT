using HeroSdJwt.Issuance;
using System.Security.Cryptography;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Unit tests for DigestCalculator.
/// Tests the computation of disclosure digests using various hash algorithms.
/// Written BEFORE implementation (TDD).
/// </summary>
public class DigestCalculatorTests
{
    [Fact]
    public void ComputeDigest_WithSha256_ReturnsBase64UrlEncodedDigest()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ"; // Example disclosure
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        Assert.NotNull(digest);
        Assert.NotEmpty(digest);
        // Base64url should not contain +, /, or =
        Assert.DoesNotContain("+", digest);
        Assert.DoesNotContain("/", digest);
        Assert.DoesNotContain("=", digest);
    }

    [Fact]
    public void ComputeDigest_WithSha256_ProducesCorrectLength()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        // SHA-256 produces 32 bytes = 256 bits
        // Base64url encoding of 32 bytes is 43 characters (without padding)
        var digestBytes = ConvertFromBase64Url(digest);
        Assert.Equal(32, digestBytes.Length);
    }

    [Fact]
    public void ComputeDigest_WithSha384_ProducesCorrectLength()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";
        var algorithm = HashAlgorithm.Sha384;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        // SHA-384 produces 48 bytes = 384 bits
        var digestBytes = ConvertFromBase64Url(digest);
        Assert.Equal(48, digestBytes.Length);
    }

    [Fact]
    public void ComputeDigest_WithSha512_ProducesCorrectLength()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";
        var algorithm = HashAlgorithm.Sha512;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        // SHA-512 produces 64 bytes = 512 bits
        var digestBytes = ConvertFromBase64Url(digest);
        Assert.Equal(64, digestBytes.Length);
    }

    [Fact]
    public void ComputeDigest_SameInputProducesSameDigest()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest1 = calculator.ComputeDigest(disclosure, algorithm);
        var digest2 = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        Assert.Equal(digest1, digest2);
    }

    [Fact]
    public void ComputeDigest_DifferentInputsProduceDifferentDigests()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure1 = "WyJzYWx0MSIsICJlbWFpbCIsICJ1c2VyQGV4YW1wbGUuY29tIl0";
        var disclosure2 = "WyJzYWx0MiIsICJlbWFpbCIsICJ1c2VyQGV4YW1wbGUuY29tIl0";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest1 = calculator.ComputeDigest(disclosure1, algorithm);
        var digest2 = calculator.ComputeDigest(disclosure2, algorithm);

        // Assert
        Assert.NotEqual(digest1, digest2);
    }

    [Fact]
    public void ComputeDigest_MatchesReferenceImplementation()
    {
        // Arrange
        var calculator = new DigestCalculator();
        // Known test vector: disclosure = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        var disclosure = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        // Compute expected digest manually
        var expectedDigest = ComputeExpectedDigest(disclosure);
        Assert.Equal(expectedDigest, digest);
    }

    [Fact]
    public void ComputeDigest_WithNullDisclosure_ThrowsArgumentNullException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var algorithm = HashAlgorithm.Sha256;

        // Act & Assert
        _ = Assert.Throws<ArgumentNullException>(() =>
            calculator.ComputeDigest(null!, algorithm));
    }

    [Fact]
    public void ComputeDigest_WithEmptyDisclosure_ThrowsArgumentException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var algorithm = HashAlgorithm.Sha256;

        // Act & Assert
        _ = Assert.Throws<ArgumentException>(() =>
            calculator.ComputeDigest(string.Empty, algorithm));
    }

    [Fact]
    public void ComputeDigest_WithWhitespaceDisclosure_ThrowsArgumentException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var algorithm = HashAlgorithm.Sha256;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            calculator.ComputeDigest("   ", algorithm));

        Assert.Contains("Disclosure cannot be empty or whitespace", exception.Message);
    }

    [Fact]
    public void ComputeDigest_WithTabOnlyDisclosure_ThrowsArgumentException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var algorithm = HashAlgorithm.Sha256;

        // Act & Assert
        _ = Assert.Throws<ArgumentException>(() =>
            calculator.ComputeDigest("\t", algorithm));
    }

    [Fact]
    public void ComputeDigest_WithNewlineOnlyDisclosure_ThrowsArgumentException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var algorithm = HashAlgorithm.Sha256;

        // Act & Assert
        _ = Assert.Throws<ArgumentException>(() =>
            calculator.ComputeDigest("\n", algorithm));
    }

    [Fact]
    public void ComputeDigest_WithUnsupportedHashAlgorithm_ThrowsArgumentException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";
        var unsupportedAlgorithm = (HashAlgorithm)999; // Invalid enum value

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            calculator.ComputeDigest(disclosure, unsupportedAlgorithm));

        Assert.Contains("Unsupported hash algorithm", exception.Message);
    }

    [Fact]
    public void ComputeDigest_DifferentAlgorithmsProduceDifferentDigests()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";

        // Act
        var sha256Digest = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var sha384Digest = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha384);
        var sha512Digest = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha512);

        // Assert
        Assert.NotEqual(sha256Digest, sha384Digest);
        Assert.NotEqual(sha256Digest, sha512Digest);
        Assert.NotEqual(sha384Digest, sha512Digest);
    }

    [Fact]
    public void ComputeDigest_WithUnicodeCharacters_ProducesCorrectDigest()
    {
        // Arrange
        var calculator = new DigestCalculator();
        // Disclosure with Unicode characters (Japanese, emoji, etc.)
        var disclosure = "WyJzYWx0IiwgIm5hbWUiLCAi5aSq6YOOIPCfjokg6J-V44K544OG44OQ44OzIl0"; // Contains UTF-8
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        Assert.NotNull(digest);
        Assert.NotEmpty(digest);

        // Verify deterministic behavior
        var digest2 = calculator.ComputeDigest(disclosure, algorithm);
        Assert.Equal(digest, digest2);
    }

    [Fact]
    public void ComputeDigest_WithSpecialCharacters_ProducesCorrectDigest()
    {
        // Arrange
        var calculator = new DigestCalculator();
        // Disclosure with special base64url characters
        var disclosure = "abc-123_XYZ"; // Contains base64url-safe characters
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        Assert.NotNull(digest);
        Assert.NotEmpty(digest);

        // Verify it's valid base64url (no +, /, =)
        Assert.DoesNotContain("+", digest);
        Assert.DoesNotContain("/", digest);
        Assert.DoesNotContain("=", digest);
    }

    [Fact]
    public void ComputeDigest_WithVeryLongDisclosure_ProducesCorrectDigest()
    {
        // Arrange
        var calculator = new DigestCalculator();
        // Create a very long disclosure (> 1KB)
        var longDisclosure = new string('A', 2000);
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(longDisclosure, algorithm);

        // Assert
        Assert.NotNull(digest);
        // SHA-256 always produces 32 bytes regardless of input size
        var digestBytes = ConvertFromBase64Url(digest);
        Assert.Equal(32, digestBytes.Length);
    }

    [Fact]
    public void ComputeDigest_WithSingleCharacterDisclosure_ProducesCorrectDigest()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "A";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest = calculator.ComputeDigest(disclosure, algorithm);

        // Assert
        Assert.NotNull(digest);
        Assert.NotEmpty(digest);

        // Verify deterministic
        var digest2 = calculator.ComputeDigest(disclosure, algorithm);
        Assert.Equal(digest, digest2);
    }

    [Fact]
    public void ComputeDigest_AllAlgorithms_ProduceValidBase64Url()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";

        // Act & Assert for each algorithm
        foreach (var algorithm in new[] { HashAlgorithm.Sha256, HashAlgorithm.Sha384, HashAlgorithm.Sha512 })
        {
            var digest = calculator.ComputeDigest(disclosure, algorithm);

            // Base64url should not contain +, /, or =
            Assert.DoesNotContain("+", digest);
            Assert.DoesNotContain("/", digest);
            Assert.DoesNotContain("=", digest);

            // Should be able to decode back
            var digestBytes = ConvertFromBase64Url(digest);
            Assert.NotEmpty(digestBytes);
        }
    }

    [Fact]
    public void ComputeDigest_SameDisclosureDifferentInstances_ProducesSameDigest()
    {
        // Arrange
        var calculator1 = new DigestCalculator();
        var calculator2 = new DigestCalculator();
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ";
        var algorithm = HashAlgorithm.Sha256;

        // Act
        var digest1 = calculator1.ComputeDigest(disclosure, algorithm);
        var digest2 = calculator2.ComputeDigest(disclosure, algorithm);

        // Assert
        Assert.Equal(digest1, digest2);
    }

    // Helper methods
    private static byte[] ConvertFromBase64Url(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - (base64.Length % 4)) % 4;
        base64 += new string('=', padding);
        return Convert.FromBase64String(base64);
    }

    private static string ComputeExpectedDigest(string disclosure)
    {
        // Compute: Base64url(SHA-256(disclosure))
        var bytes = System.Text.Encoding.UTF8.GetBytes(disclosure);
        var hash = SHA256.HashData(bytes);
        return ConvertToBase64Url(hash);
    }

    private static string ConvertToBase64Url(byte[] bytes)
    {
        return Base64UrlEncoder.Encode(bytes);
    }
}
