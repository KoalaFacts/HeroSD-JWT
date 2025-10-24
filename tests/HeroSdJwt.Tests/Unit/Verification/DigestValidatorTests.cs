using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Unit.Verification;

/// <summary>
/// Unit tests for DigestValidator.
/// Tests constant-time comparison and digest validation logic.
/// </summary>
public class DigestValidatorTests
{
    private static byte[] GenerateSecureTestKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void ValidateDigest_WithMatchingDigest_ReturnsTrue()
    {
        // Arrange
        var disclosure = CreateTestDisclosure("email", "user@example.com");
        var calculator = new DigestCalculator();
        var digestValue = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var expectedDigest = new Digest(digestValue, HashAlgorithm.Sha256);

        // Act
        var result = DigestValidator.ValidateDigest(disclosure, expectedDigest, HashAlgorithm.Sha256);

        // Assert
        Assert.True(result, "Digest validation should succeed for matching digest");
    }

    [Fact]
    public void ValidateDigest_WithNonMatchingDigest_ReturnsFalse()
    {
        // Arrange
        var disclosure = CreateTestDisclosure("email", "user@example.com");
        var differentDisclosure = CreateTestDisclosure("email", "different@example.com");
        var calculator = new DigestCalculator();
        var wrongDigestValue = calculator.ComputeDigest(differentDisclosure, HashAlgorithm.Sha256);
        var wrongDigest = new Digest(wrongDigestValue, HashAlgorithm.Sha256);

        // Act
        var result = DigestValidator.ValidateDigest(disclosure, wrongDigest, HashAlgorithm.Sha256);

        // Assert
        Assert.False(result, "Digest validation should fail for non-matching digest");
    }

    [Fact]
    public void ValidateDigest_WithNullDisclosure_ThrowsArgumentNullException()
    {
        // Arrange
        var digest = new Digest("test", HashAlgorithm.Sha256);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            DigestValidator.ValidateDigest(null!, digest, HashAlgorithm.Sha256));
    }

    [Fact]
    public void ValidateDigest_WithDifferentAlgorithms_ReturnsCorrectResult()
    {
        // Arrange - Create disclosure and compute digest with SHA-256
        var disclosure = CreateTestDisclosure("name", "John Doe");
        var calculator = new DigestCalculator();
        var sha256DigestValue = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var sha256Digest = new Digest(sha256DigestValue, HashAlgorithm.Sha256);

        var sha384DigestValue = calculator.ComputeDigest(disclosure, HashAlgorithm.Sha384);
        var sha384Digest = new Digest(sha384DigestValue, HashAlgorithm.Sha384);

        // Act
        var sha256Result = DigestValidator.ValidateDigest(disclosure, sha256Digest, HashAlgorithm.Sha256);
        var sha384Result = DigestValidator.ValidateDigest(disclosure, sha384Digest, HashAlgorithm.Sha384);

        // Assert
        Assert.True(sha256Result, "SHA-256 digest should validate correctly");
        Assert.True(sha384Result, "SHA-384 digest should validate correctly");
    }

    [Fact]
    public void ValidateAllDigests_WithAllMatchingDigests_ReturnsTrue()
    {
        // Arrange
        var disclosure1 = CreateTestDisclosure("email", "user@example.com");
        var disclosure2 = CreateTestDisclosure("age", "30");
        var disclosures = new[] { disclosure1, disclosure2 };

        var calculator = new DigestCalculator();
        var digest1 = new Digest(calculator.ComputeDigest(disclosure1, HashAlgorithm.Sha256), HashAlgorithm.Sha256);
        var digest2 = new Digest(calculator.ComputeDigest(disclosure2, HashAlgorithm.Sha256), HashAlgorithm.Sha256);
        var expectedDigests = new[] { digest1, digest2 };

        // Act
        var result = DigestValidator.ValidateAllDigests(disclosures, expectedDigests, HashAlgorithm.Sha256);

        // Assert
        Assert.True(result, "All digests should validate successfully");
    }

    [Fact]
    public void ValidateAllDigests_WithOneMismatchedDigest_ReturnsFalse()
    {
        // Arrange
        var disclosure1 = CreateTestDisclosure("email", "user@example.com");
        var disclosure2 = CreateTestDisclosure("age", "30");
        var wrongDisclosure = CreateTestDisclosure("age", "31"); // Wrong value
        var disclosures = new[] { disclosure1, disclosure2 };

        var calculator = new DigestCalculator();
        var digest1 = new Digest(calculator.ComputeDigest(disclosure1, HashAlgorithm.Sha256), HashAlgorithm.Sha256);
        var wrongDigest2 = new Digest(calculator.ComputeDigest(wrongDisclosure, HashAlgorithm.Sha256), HashAlgorithm.Sha256);
        var expectedDigests = new[] { digest1, wrongDigest2 };

        // Act
        var result = DigestValidator.ValidateAllDigests(disclosures, expectedDigests, HashAlgorithm.Sha256);

        // Assert
        Assert.False(result, "Validation should fail when one digest doesn't match");
    }

    [Fact]
    public void ValidateAllDigests_WithEmptyLists_ReturnsTrue()
    {
        // Arrange
        var disclosures = Array.Empty<string>();
        var expectedDigests = Array.Empty<Digest>();

        // Act
        var result = DigestValidator.ValidateAllDigests(disclosures, expectedDigests, HashAlgorithm.Sha256);

        // Assert
        Assert.True(result, "Validation should succeed with empty lists");
    }

    [Fact]
    public void ValidateAllDigests_WithNullDisclosures_ThrowsArgumentNullException()
    {
        // Arrange
        var expectedDigests = Array.Empty<Digest>();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            DigestValidator.ValidateAllDigests(null!, expectedDigests, HashAlgorithm.Sha256));
    }

    [Fact]
    public void ValidateAllDigests_WithNullExpectedDigests_ThrowsArgumentNullException()
    {
        // Arrange
        var disclosures = Array.Empty<string>();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            DigestValidator.ValidateAllDigests(disclosures, null!, HashAlgorithm.Sha256));
    }

    [Fact]
    public void ValidateAllDigests_WithDisclosuresInDifferentOrder_ReturnsTrue()
    {
        // Arrange - Order shouldn't matter for validation
        var disclosure1 = CreateTestDisclosure("email", "user@example.com");
        var disclosure2 = CreateTestDisclosure("age", "30");
        var disclosures = new[] { disclosure1, disclosure2 };

        var calculator = new DigestCalculator();
        var digest1 = new Digest(calculator.ComputeDigest(disclosure1, HashAlgorithm.Sha256), HashAlgorithm.Sha256);
        var digest2 = new Digest(calculator.ComputeDigest(disclosure2, HashAlgorithm.Sha256), HashAlgorithm.Sha256);

        // Expected digests in reverse order
        var expectedDigests = new[] { digest2, digest1 };

        // Act
        var result = DigestValidator.ValidateAllDigests(disclosures, expectedDigests, HashAlgorithm.Sha256);

        // Assert
        Assert.True(result, "Digest validation should be order-independent");
    }

    [Fact]
    public void ValidateAllDigests_WithExtraExpectedDigests_ReturnsTrue()
    {
        // Arrange - Having more expected digests than disclosures is valid (selective disclosure)
        var disclosure1 = CreateTestDisclosure("email", "user@example.com");
        var disclosures = new[] { disclosure1 };

        var calculator = new DigestCalculator();
        var digest1 = new Digest(calculator.ComputeDigest(disclosure1, HashAlgorithm.Sha256), HashAlgorithm.Sha256);
        var extraDisclosure = CreateTestDisclosure("age", "30");
        var digest2 = new Digest(calculator.ComputeDigest(extraDisclosure, HashAlgorithm.Sha256), HashAlgorithm.Sha256);

        var expectedDigests = new[] { digest1, digest2 };

        // Act
        var result = DigestValidator.ValidateAllDigests(disclosures, expectedDigests, HashAlgorithm.Sha256);

        // Assert
        Assert.True(result, "Validation should succeed with fewer disclosures than expected (selective disclosure)");
    }

    /// <summary>
    /// Helper method to create a test disclosure in the correct format.
    /// </summary>
    private static string CreateTestDisclosure(string claimName, string claimValue)
    {
        var generator = new DisclosureGenerator();
        var valueElement = JsonDocument.Parse($"\"{claimValue}\"").RootElement;
        return generator.GenerateDisclosure(claimName, valueElement);
    }
}
