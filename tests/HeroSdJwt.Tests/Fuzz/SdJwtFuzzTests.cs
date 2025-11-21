using CsCheck;
using HeroSdJwt.Encoding;
using HeroSdJwt.Extensions;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Fuzz;

/// <summary>
/// Fuzz tests using CsCheck for property-based testing.
/// These tests generate random inputs to discover edge cases and ensure robustness.
/// </summary>
public class SdJwtFuzzTests
{
    [Fact]
    public void IssuanceWithRandomClaims_NeverCrashes()
    {
        Gen.Dictionary(Gen.String[1, 50], Gen.String[1, 1000])[1, 20]
            .Sample(claims =>
            {
                // Skip reserved claims
                if (claims.Keys.Any(k => Constants.ReservedClaims.Contains(k)))
                {
                    return;
                }

                // Arrange
                var key = new byte[32];
                RandomNumberGenerator.Fill(key);

                var issuer = TestHelpers.CreateIssuer();

                try
                {
                    // Act - Issue SD-JWT with random claims
                    var result = issuer.CreateSdJwt(
                        claims.ToDictionary(x => x.Key, x => (object)x.Value),
                        [.. claims.Keys],
                        key,
                        Primitives.HashAlgorithm.Sha256,
                        SignatureAlgorithm.HS256);

                    // Assert - Should successfully create JWT
                    Assert.NotNull(result);
                }
                catch (ArgumentException)
                {
                    // Expected for invalid inputs
                }
                catch (InvalidOperationException)
                {
                    // Expected for certain invalid states
                }
            }, iter: 1000);
    }

    [Fact]
    public void Base64UrlEncoding_RoundTrip()
    {
        Gen.Byte.Array[1, 10000]
            .Sample(data =>
            {
                // Arrange & Act
                var encoded = Base64UrlEncoder.Encode(data);
                var decoded = Base64UrlEncoder.DecodeBytes(encoded);

                // Assert
                Assert.True(data.SequenceEqual(decoded), "Round-trip encoding should preserve data");
            }, iter: 1000);
    }

    [Fact]
    public void MalformedJwt_VerificationHandlesGracefully()
    {
        Gen.String[1, 1000]
            .Sample(malformedJwt =>
            {
                // Arrange
                var key = new byte[32];
                RandomNumberGenerator.Fill(key);

                var verifier = TestHelpers.CreateVerifier();

                try
                {
                    // Act - Try to verify malformed JWT
                    var result = verifier.TryVerifyPresentation(malformedJwt, key);

                    // Assert - Should never throw, always return result
                    Assert.False(result.IsValid, "Malformed JWT should be identified as invalid");
                }
                catch
                {
                    // Should not throw - TryVerifyPresentation should catch all exceptions
                    Assert.Fail("TryVerifyPresentation should not throw exceptions");
                }
            }, iter: 1000);
    }

    [Fact]
    public void RandomDisclosures_ParsingNeverCrashes()
    {
        Gen.String[1, 100].Array[1, 50]
            .Sample(randomDisclosures =>
            {
                // Arrange
                var key = new byte[32];
                RandomNumberGenerator.Fill(key);

                var issuer = TestHelpers.CreateIssuer();
                var validClaims = new Dictionary<string, object>
                {
                    ["sub"] = "test-user",
                    ["name"] = "Test User"
                };

                // Create a valid SD-JWT
                var sdJwt = issuer.CreateSdJwt(
                    validClaims,
                    ["name"],
                    key,
                    Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256);

                // Act - Create presentation with random disclosures appended
                var presentation = sdJwt.Jwt + "~" + string.Join("~", randomDisclosures) + "~";

                var verifier = TestHelpers.CreateVerifier();

                try
                {
                    var result = verifier.TryVerifyPresentation(presentation, key);

                    // Assert - Should handle gracefully (result may be valid or invalid)
                    Assert.True(true, "Random disclosures handled without crash");
                }
                catch
                {
                    Assert.Fail("Random disclosures should not cause crash");
                }
            }, iter: 500);
    }

    [Fact]
    public void LargePayloads_HandledCorrectly()
    {
        Gen.Int[1, 1000]
            .Sample(size =>
            {
                // Arrange
                var key = new byte[32];
                RandomNumberGenerator.Fill(key);

                var claims = new Dictionary<string, object>();
                for (int i = 0; i < size; i++)
                {
                    claims[$"claim_{i}"] = $"value_{i}";
                }

                var issuer = TestHelpers.CreateIssuer();

                try
                {
                    // Act - Create SD-JWT with many claims
                    var sdJwt = issuer.CreateSdJwt(
                        claims,
                        [.. claims.Keys.Take(Math.Min(size, 50))], // Limit selective disclosure
                        key,
                        Primitives.HashAlgorithm.Sha256,
                        SignatureAlgorithm.HS256);

                    // Assert
                    Assert.NotNull(sdJwt);
                }
                catch (ArgumentException)
                {
                    // Expected when exceeding limits
                    Assert.True(true, "Large payload correctly rejected");
                }
            }, iter: 500);
    }

    [Fact]
    public void KeyBindingWithRandomKeys_VerificationCorrect()
    {
        Gen.Byte.Array[32, 256]
            .Sample(randomKey =>
            {
                // Arrange
                using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

                var issuerKey = new byte[32];
                RandomNumberGenerator.Fill(issuerKey);

                var claims = new Dictionary<string, object>
                {
                    ["sub"] = "user123",
                    ["name"] = "Test User"
                };

                var issuer = TestHelpers.CreateIssuer();
                var sdJwt = issuer.CreateSdJwt(
                    claims,
                    ["name"],
                    issuerKey,
                    Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256,
                    holderPublicKey);

                var verifier = TestHelpers.CreateVerifier();

                try
                {
                    // Act - Try to verify with random key
                    var result = verifier.TryVerifyPresentation(
                        sdJwt.ToPresentation("name"),
                        randomKey); // Wrong key

                    // Assert - Should fail verification (unless by extremely rare chance it's the right key)
                    Assert.True(!result.IsValid || randomKey.SequenceEqual(issuerKey),
                        "Random key should fail verification");
                }
                catch
                {
                    Assert.Fail("Random key should not cause exception");
                }
            }, iter: 500);
    }

    [Fact]
    public void NestedObjects_HandledCorrectly()
    {
        Gen.Dictionary(Gen.String[1, 20], Gen.String[1, 100])[1, 5]
            .Sample(nestedData =>
            {
                // Arrange
                var key = new byte[32];
                RandomNumberGenerator.Fill(key);

                var claims = new Dictionary<string, object>
                {
                    ["sub"] = "user123",
                    ["nested"] = nestedData
                };

                var issuer = TestHelpers.CreateIssuer();

                try
                {
                    // Act - Create SD-JWT with nested object
                    var sdJwt = issuer.CreateSdJwt(
                        claims,
                        ["nested"],
                        key,
                        Primitives.HashAlgorithm.Sha256,
                        SignatureAlgorithm.HS256);

                    // Assert
                    Assert.NotNull(sdJwt);

                    // Verify round-trip
                    var verifier = TestHelpers.CreateVerifier();
                    var result = verifier.TryVerifyPresentation(
                        sdJwt.ToPresentation("nested"),
                        key);

                    Assert.True(result.IsValid, "Nested objects should be handled correctly");
                }
                catch (ArgumentException)
                {
                    // Expected for certain invalid nested structures
                    Assert.True(true, "Invalid nested structure correctly rejected");
                }
            }, iter: 500);
    }

    [Fact]
    public void EdgeCaseStrings_HandledSafely()
    {
        var edgeCases = new[]
        {
            "", // Empty string
            " ", // Whitespace
            "\n\r\t", // Special characters
            "a".PadRight(10000, 'a'), // Very long string
            "\"quoted\"", // Quotes
            "\\escaped\\", // Backslashes
            /*lang=json,strict*/
                                 "{\"json\":true}", // JSON-like
            "null", // Null string
            "undefined", // Undefined string
            "<script>alert('xss')</script>", // XSS attempt
            "'; DROP TABLE users; --", // SQL injection attempt
            new string((char)0, 5), // Null characters
            "🔐🎉", // Emoji
        };

        foreach (var edgeCase in edgeCases)
        {
            // Arrange
            var key = new byte[32];
            RandomNumberGenerator.Fill(key);

            var claims = new Dictionary<string, object>
            {
                ["sub"] = "user123",
                ["test"] = edgeCase
            };

            var issuer = TestHelpers.CreateIssuer();

            try
            {
                // Act
                var sdJwt = issuer.CreateSdJwt(
                    claims,
                    ["test"],
                    key,
                    Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256);

                // Assert - Should either succeed or throw expected exception
                Assert.NotNull(sdJwt);
            }
            catch (ArgumentException)
            {
                // Expected for invalid inputs
            }
            catch (InvalidOperationException)
            {
                // Expected for certain edge cases
            }
        }
    }
}
