using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using System.Text;
using Xunit;
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
        Assert.Throws<ArgumentNullException>(() =>
            calculator.ComputeDigest(null!, algorithm));
    }

    [Fact]
    public void ComputeDigest_WithEmptyDisclosure_ThrowsArgumentException()
    {
        // Arrange
        var calculator = new DigestCalculator();
        var algorithm = HashAlgorithm.Sha256;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            calculator.ComputeDigest(string.Empty, algorithm));
    }

    // Helper methods
    private static byte[] ConvertFromBase64Url(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
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
