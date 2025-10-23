using HeroSdJwt.Common;
using HeroSdJwt.Verification;
using Xunit;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Security tests for algorithm confusion prevention.
/// Validates protection against the "none" algorithm attack and other algorithm-related vulnerabilities.
/// Written BEFORE implementation (TDD).
/// </summary>
public class AlgorithmSecurityTests
{
    [Fact]
    public void VerifyPresentation_WithNoneAlgorithm_ThrowsAlgorithmConfusionException()
    {
        // Arrange
        var verifier = new SdJwtVerifier();

        // Create a JWT with "none" algorithm
        // Header: {"alg":"none","typ":"JWT"}
        var header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        // Payload: {"sub":"user123","_sd_alg":"sha-256","_sd":[]}
        var payload = "eyJzdWIiOiJ1c2VyMTIzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOltdfQ";
        // Signature: empty
        var signature = "";

        var maliciousJwt = $"{header}.{payload}.{signature}";
        var presentation = maliciousJwt + "~"; // Combined format

        var publicKey = new byte[32]; // Dummy key

        // Act & Assert
        var exception = Assert.Throws<AlgorithmConfusionException>(() =>
            verifier.VerifyPresentation(presentation, publicKey));

        Assert.Equal(ErrorCode.AlgorithmConfusion, exception.ErrorCode);
    }

    [Fact]
    public void VerifyPresentation_WithNoneAlgorithmUppercase_ThrowsAlgorithmConfusionException()
    {
        // Arrange
        var verifier = new SdJwtVerifier();

        // Create a JWT with "NONE" algorithm (uppercase variant)
        // Header: {"alg":"NONE","typ":"JWT"}
        var header = "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0";
        var payload = "eyJzdWIiOiJ1c2VyMTIzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOltdfQ";
        var signature = "";

        var maliciousJwt = $"{header}.{payload}.{signature}";
        var presentation = maliciousJwt + "~";

        var publicKey = new byte[32];

        // Act & Assert
        Assert.Throws<AlgorithmConfusionException>(() =>
            verifier.VerifyPresentation(presentation, publicKey));
    }

    [Fact]
    public void VerifyPresentation_WithUnsupportedAlgorithm_ThrowsAlgorithmNotSupportedException()
    {
        // Arrange
        var verifier = new SdJwtVerifier();

        // Create a JWT with an unsupported algorithm (e.g., "HS384")
        // Header: {"alg":"HS384","typ":"JWT"}
        var header = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9";
        var payload = "eyJzdWIiOiJ1c2VyMTIzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOltdfQ";
        var signature = "dW5zdXBwb3J0ZWQ"; // Dummy signature

        var jwt = $"{header}.{payload}.{signature}";
        var presentation = jwt + "~";

        var publicKey = new byte[32];

        // Act & Assert
        Assert.Throws<AlgorithmNotSupportedException>(() =>
            verifier.VerifyPresentation(presentation, publicKey));
    }

    [Fact]
    public void VerifyPresentation_WithMissingAlgorithm_ThrowsSdJwtException()
    {
        // Arrange
        var verifier = new SdJwtVerifier();

        // Create a JWT header without "alg" claim
        // Header: {"typ":"JWT"}
        var header = "eyJ0eXAiOiJKV1QifQ";
        var payload = "eyJzdWIiOiJ1c2VyMTIzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOltdfQ";
        var signature = "c2lnbmF0dXJl";

        var jwt = $"{header}.{payload}.{signature}";
        var presentation = jwt + "~";

        var publicKey = new byte[32];

        // Act & Assert
        Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, publicKey));
    }

    [Fact]
    public void VerifyPresentation_RejectsAlgorithmSwitching()
    {
        // Arrange
        var verifier = new SdJwtVerifier();

        // This test validates that the verifier doesn't accept a JWT
        // signed with one algorithm but claiming another in the header
        // This is a common JWT vulnerability

        // For this test, we'll need a proper implementation
        // For now, we define the expected behavior

        // Create JWT claiming RS256 but actually using HS256
        var header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // Claims RS256
        var payload = "eyJzdWIiOiJ1c2VyMTIzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOltdfQ";
        var signature = "aG1hY19zaWduYXR1cmU"; // Actually HMAC signature

        var jwt = $"{header}.{payload}.{signature}";
        var presentation = jwt + "~";

        var publicKey = new byte[32];

        // Act & Assert
        // Should fail signature verification
        var result = verifier.TryVerifyPresentation(presentation, publicKey);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void VerifyPresentation_WithHashAlgorithmMismatch_Fails()
    {
        // Arrange
        var verifier = new SdJwtVerifier();

        // Create a presentation where JWT claims sha-256 but disclosures use sha-512
        // This should be detected and rejected

        // Header: {"alg":"RS256","typ":"JWT"}
        var header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        // Payload claims sha-256
        var payload = "eyJzdWIiOiJ1c2VyMTIzIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOlsiZGlnZXN0MSJdfQ";
        var signature = "c2lnbmF0dXJl";

        var jwt = $"{header}.{payload}.{signature}";
        var disclosure = "WyJzYWx0IiwgImVtYWlsIiwgInVzZXJAZXhhbXBsZS5jb20iXQ"; // Disclosure
        var presentation = $"{jwt}~{disclosure}~";

        var publicKey = new byte[32];

        // Act - Verify with SHA-512 (mismatch)
        var result = verifier.TryVerifyPresentation(presentation, publicKey, HashAlgorithm.Sha512);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.HashAlgorithmMismatch, result.Errors);
    }

    [Fact]
    public void CreateSdJwt_NeverUsesNoneAlgorithm()
    {
        // Arrange
        var issuer = new Issuance.SdJwtIssuer();
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var selectiveClaims = Array.Empty<string>();
        var signingKey = new byte[32];

        // Act - Create SD-JWT with various hash algorithms
        foreach (HashAlgorithm hashAlg in Enum.GetValues<HashAlgorithm>())
        {
            var sdJwt = issuer.CreateSdJwt(claims, selectiveClaims, signingKey, hashAlg);

            // Assert - Decode header and verify algorithm is not "none"
            var jwtParts = sdJwt.Jwt.Split('.');
            var headerBase64 = jwtParts[0];
            var headerJson = DecodeBase64Url(headerBase64);

            Assert.DoesNotContain("\"none\"", headerJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("\"alg\":\"none\"", headerJson, StringComparison.OrdinalIgnoreCase);
        }
    }

    // Helper methods
    private static string DecodeBase64Url(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - base64.Length % 4) % 4;
        base64 += new string('=', padding);
        var bytes = Convert.FromBase64String(base64);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
