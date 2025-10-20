using HeroSdJwt.Issuance;
using System.Text;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Security tests for salt generation.
/// Validates cryptographic properties required by the SD-JWT specification.
/// Written BEFORE implementation (TDD).
/// </summary>
public class SaltSecurityTests
{
    [Fact]
    public void GenerateDisclosure_SaltsAreUnique_Over1000Iterations()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var salts = new HashSet<string>();
        const int iterations = 1000;

        // Act
        for (int i = 0; i < iterations; i++)
        {
            var disclosure = generator.GenerateDisclosure(claimName, claimValue);
            var decoded = DecodeDisclosure(disclosure);
            var salt = decoded[0].GetString()!;
            salts.Add(salt);
        }

        // Assert
        // All salts should be unique (no collisions)
        Assert.Equal(iterations, salts.Count);
    }

    [Fact]
    public void GenerateDisclosure_SaltsHaveHighEntropy()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        const int iterations = 100;
        var salts = new List<byte[]>();

        // Act
        for (int i = 0; i < iterations; i++)
        {
            var disclosure = generator.GenerateDisclosure(claimName, claimValue);
            var decoded = DecodeDisclosure(disclosure);
            var saltString = decoded[0].GetString()!;
            var saltBytes = ConvertFromBase64UrlToBytes(saltString);
            salts.Add(saltBytes);
        }

        // Assert
        // Check that salts are not sequential or predictable
        // Compare each salt with the next one - they should differ significantly
        for (int i = 0; i < salts.Count - 1; i++)
        {
            var diffCount = 0;
            for (int j = 0; j < Math.Min(salts[i].Length, salts[i + 1].Length); j++)
            {
                if (salts[i][j] != salts[i + 1][j])
                {
                    diffCount++;
                }
            }

            // At least 50% of bytes should differ (high entropy indicator)
            var minDifferences = salts[i].Length / 2;
            Assert.True(diffCount >= minDifferences,
                $"Salt {i} and {i + 1} are too similar: only {diffCount}/{salts[i].Length} bytes differ");
        }
    }

    [Fact]
    public void GenerateDisclosure_SaltLengthMeetsMinimumRequirement()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        const int iterations = 10;
        const int minimumSaltBytes = 16; // 128 bits

        // Act & Assert
        for (int i = 0; i < iterations; i++)
        {
            var disclosure = generator.GenerateDisclosure(claimName, claimValue);
            var decoded = DecodeDisclosure(disclosure);
            var saltString = decoded[0].GetString()!;
            var saltBytes = ConvertFromBase64UrlToBytes(saltString);

            Assert.True(saltBytes.Length >= minimumSaltBytes,
                $"Salt length is {saltBytes.Length} bytes, but minimum required is {minimumSaltBytes} bytes (128 bits)");
        }
    }

    [Fact]
    public void GenerateDisclosure_SaltsUseBase64UrlEncoding()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;

        // Act
        var disclosure = generator.GenerateDisclosure(claimName, claimValue);
        var decoded = DecodeDisclosure(disclosure);
        var salt = decoded[0].GetString()!;

        // Assert
        // Base64url must not contain +, /, or =
        Assert.DoesNotContain("+", salt);
        Assert.DoesNotContain("/", salt);
        Assert.DoesNotContain("=", salt);

        // Should only contain base64url alphabet: A-Z, a-z, 0-9, -, _
        Assert.Matches("^[A-Za-z0-9_-]+$", salt);
    }

    [Fact]
    public void GenerateDisclosure_ConcurrentCallsProduceUniqueSalts()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        var salts = new System.Collections.Concurrent.ConcurrentBag<string>();
        const int iterations = 100;

        // Act
        // Generate disclosures concurrently to test thread safety of RNG
        Parallel.For(0, iterations, _ =>
        {
            var disclosure = generator.GenerateDisclosure(claimName, claimValue);
            var decoded = DecodeDisclosure(disclosure);
            var salt = decoded[0].GetString()!;
            salts.Add(salt);
        });

        // Assert
        // All salts should be unique even when generated concurrently
        var uniqueSalts = new HashSet<string>(salts);
        Assert.Equal(iterations, uniqueSalts.Count);
    }

    [Fact]
    public void GenerateDisclosure_SaltsDoNotContainPredictablePatterns()
    {
        // Arrange
        var generator = new DisclosureGenerator();
        var claimName = "test";
        var claimValue = JsonDocument.Parse("\"value\"").RootElement;
        const int iterations = 50;

        // Act
        for (int i = 0; i < iterations; i++)
        {
            var disclosure = generator.GenerateDisclosure(claimName, claimValue);
            var decoded = DecodeDisclosure(disclosure);
            var saltString = decoded[0].GetString()!;
            var saltBytes = ConvertFromBase64UrlToBytes(saltString);

            // Assert - Check for predictable patterns
            // No salt should be all zeros
            Assert.False(saltBytes.All(b => b == 0), "Salt contains all zeros (predictable pattern)");

            // No salt should be all same value
            Assert.False(saltBytes.All(b => b == saltBytes[0]), "Salt contains all same value (predictable pattern)");

            // No salt should be sequential
            var isSequential = true;
            for (int j = 1; j < saltBytes.Length; j++)
            {
                if (saltBytes[j] != (byte)(saltBytes[j - 1] + 1))
                {
                    isSequential = false;
                    break;
                }
            }
            Assert.False(isSequential, "Salt contains sequential bytes (predictable pattern)");
        }
    }

    // Helper methods
    private static JsonElement DecodeDisclosure(string base64UrlDisclosure)
    {
        var base64 = ConvertFromBase64Url(base64UrlDisclosure);
        var bytes = Convert.FromBase64String(base64);
        var json = Encoding.UTF8.GetString(bytes);
        return JsonDocument.Parse(json).RootElement;
    }

    private static string ConvertFromBase64Url(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
        return base64 + new string('=', padding);
    }

    private static byte[] ConvertFromBase64UrlToBytes(string base64Url)
    {
        var base64 = ConvertFromBase64Url(base64Url);
        return Convert.FromBase64String(base64);
    }
}
