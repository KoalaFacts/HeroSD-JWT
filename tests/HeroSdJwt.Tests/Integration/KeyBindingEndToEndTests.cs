using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Base64UrlEncoder = HeroSdJwt.Encoding.Base64UrlEncoder;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Integration;

/// <summary>
/// End-to-end tests for complete key binding workflow.
/// Tests the full lifecycle: issuance with cnf claim → presentation with key binding → verification.
/// </summary>
public class KeyBindingEndToEndTests
{
    [Fact]
    public void CompleteKeyBindingWorkflow_WithValidKeyBinding_SuccessfullyVerifies()
    {
        // Arrange - Setup issuer's signing key
        var issuerSigningKey = new byte[32];
        RandomNumberGenerator.Fill(issuerSigningKey);

        // Generate holder's key pair (ECDSA P-256)
        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holderEcdsa.ExportECPrivateKey();
        var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

        // Step 1: Issuer creates SD-JWT with cnf claim
        var issuer = new SdJwtIssuer();
        var audience = "https://verifier.example.com";
        var claims = new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "aud", audience },  // Add audience claim
            { "name", "John Doe" },
            { "email", "john@example.com" },
            { "age", 30 }
        };

        var selectivelyDisclosableClaims = new[] { "name", "email", "age" };
        var sdJwt = issuer.CreateSdJwt(
            claims,
            selectivelyDisclosableClaims,
            issuerSigningKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        // Verify cnf claim is present
        Assert.NotNull(sdJwt);

        // Step 2: Holder creates presentation with key binding
        var presenter = new SdJwtPresenter();

        // Build the SD-JWT string for hashing (everything that will be in presentation except KB-JWT)
        // Format: JWT~disclosure1~disclosure2~...~
        var sdJwtParts = new List<string> { sdJwt.Jwt };

        // Get the disclosures for the selected claims
        var claimToDisclosure = new Dictionary<string, string>();
        foreach (var disclosure in sdJwt.Disclosures)
        {
            try
            {
                var decodedJson = Convert.FromBase64String(
                    disclosure.Replace('-', '+').Replace('_', '/')
                        .PadRight(disclosure.Length + (4 - disclosure.Length % 4) % 4, '='));
                var decodedString = System.Text.Encoding.UTF8.GetString(decodedJson);
                var array = System.Text.Json.JsonDocument.Parse(decodedString).RootElement;
                if (array.GetArrayLength() == 3)
                {
                    var claimName = array[1].GetString();
                    if (claimName != null)
                    {
                        claimToDisclosure[claimName] = disclosure;
                    }
                }
            }
            catch { }
        }

        // Add the selected disclosures
        if (claimToDisclosure.TryGetValue("name", out var nameDisclosure))
        {
            sdJwtParts.Add(nameDisclosure);
        }
        if (claimToDisclosure.TryGetValue("email", out var emailDisclosure))
        {
            sdJwtParts.Add(emailDisclosure);
        }

        // Compute SD-JWT hash: hash of "JWT~disclosure1~disclosure2~" (with trailing tilde)
        var sdJwtString = string.Join("~", sdJwtParts) + "~";
        using var sha256 = SHA256.Create();
        var sdJwtHashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(sdJwtString));
        var sdJwtHash = Base64UrlEncoder.Encode(sdJwtHashBytes);

        // Generate key binding JWT
        var keyBindingGenerator = new KeyBindingGenerator();
        var nonce = "random_nonce_12345";
        var keyBindingJwt = keyBindingGenerator.CreateKeyBindingJwt(
            holderPrivateKey,
            sdJwtHash,
            audience,
            nonce);

        // Create final presentation with key binding
        var finalPresentation = presenter.CreatePresentation(
            sdJwt,
            new[] { "name", "email" },
            keyBindingJwt);

        var finalPresentationString = presenter.FormatPresentation(finalPresentation);

        // Step 3: Verifier validates presentation with key binding
        var verificationOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = audience,
            ExpectedNonce = nonce
        };
        var verifier = new SdJwtVerifier(verificationOptions);

        // Act
        var result = verifier.VerifyPresentation(
            finalPresentationString,
            issuerSigningKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Contains("name", result.DisclosedClaims.Keys);
        Assert.Contains("email", result.DisclosedClaims.Keys);
        Assert.Equal("John Doe", result.DisclosedClaims["name"].GetString());
        Assert.Equal("john@example.com", result.DisclosedClaims["email"].GetString());
    }

    [Fact]
    public void CompleteKeyBindingWorkflow_WithWrongAudience_FailsVerification()
    {
        // Arrange
        var issuerSigningKey = new byte[32];
        RandomNumberGenerator.Fill(issuerSigningKey);

        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holderEcdsa.ExportECPrivateKey();
        var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

        var issuer = new SdJwtIssuer();
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            issuerSigningKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        var presenter = new SdJwtPresenter();
        var presentationWithoutKb = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationStringWithoutKb = presenter.FormatPresentation(presentationWithoutKb);

        using var sha256 = SHA256.Create();
        var sdJwtHashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(presentationStringWithoutKb));
        var sdJwtHash = Base64UrlEncoder.Encode(sdJwtHashBytes);

        var keyBindingGenerator = new KeyBindingGenerator();
        var keyBindingJwt = keyBindingGenerator.CreateKeyBindingJwt(
            holderPrivateKey,
            sdJwtHash,
            "https://wrong-audience.com",  // Wrong audience
            "nonce123");

        var finalPresentation = presenter.CreatePresentationWithAllClaims(sdJwt, keyBindingJwt);
        var finalPresentationString = presenter.FormatPresentation(finalPresentation);

        var verificationOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = "https://verifier.example.com",  // Expected audience
            ExpectedNonce = "nonce123"
        };
        var verifier = new SdJwtVerifier(verificationOptions);

        // Act
        var result = verifier.TryVerifyPresentation(
            finalPresentationString,
            issuerSigningKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void CompleteKeyBindingWorkflow_WithWrongNonce_FailsVerification()
    {
        // Arrange
        var issuerSigningKey = new byte[32];
        RandomNumberGenerator.Fill(issuerSigningKey);

        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holderEcdsa.ExportECPrivateKey();
        var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

        var issuer = new SdJwtIssuer();
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            issuerSigningKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        var presenter = new SdJwtPresenter();
        var presentationWithoutKb = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationStringWithoutKb = presenter.FormatPresentation(presentationWithoutKb);

        using var sha256 = SHA256.Create();
        var sdJwtHashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(presentationStringWithoutKb));
        var sdJwtHash = Base64UrlEncoder.Encode(sdJwtHashBytes);

        var keyBindingGenerator = new KeyBindingGenerator();
        var audience = "https://verifier.example.com";
        var keyBindingJwt = keyBindingGenerator.CreateKeyBindingJwt(
            holderPrivateKey,
            sdJwtHash,
            audience,
            "wrong_nonce");  // Wrong nonce

        var finalPresentation = presenter.CreatePresentationWithAllClaims(sdJwt, keyBindingJwt);
        var finalPresentationString = presenter.FormatPresentation(finalPresentation);

        var verificationOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = audience,
            ExpectedNonce = "expected_nonce"  // Expected nonce
        };
        var verifier = new SdJwtVerifier(verificationOptions);

        // Act
        var result = verifier.TryVerifyPresentation(
            finalPresentationString,
            issuerSigningKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void CompleteKeyBindingWorkflow_WithWrongPrivateKey_FailsVerification()
    {
        // Arrange
        var issuerSigningKey = new byte[32];
        RandomNumberGenerator.Fill(issuerSigningKey);

        // Holder's key pair
        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

        // Attacker's key pair
        using var attackerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attackerPrivateKey = attackerEcdsa.ExportECPrivateKey();

        var issuer = new SdJwtIssuer();
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            issuerSigningKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        var presenter = new SdJwtPresenter();
        var presentationWithoutKb = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationStringWithoutKb = presenter.FormatPresentation(presentationWithoutKb);

        using var sha256 = SHA256.Create();
        var sdJwtHashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(presentationStringWithoutKb));
        var sdJwtHash = Base64UrlEncoder.Encode(sdJwtHashBytes);

        // Attacker tries to create key binding with their own private key
        var keyBindingGenerator = new KeyBindingGenerator();
        var audience = "https://verifier.example.com";
        var nonce = "nonce123";
        var keyBindingJwt = keyBindingGenerator.CreateKeyBindingJwt(
            attackerPrivateKey,  // Wrong private key
            sdJwtHash,
            audience,
            nonce);

        var finalPresentation = presenter.CreatePresentationWithAllClaims(sdJwt, keyBindingJwt);
        var finalPresentationString = presenter.FormatPresentation(finalPresentation);

        var verificationOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = audience,
            ExpectedNonce = nonce
        };
        var verifier = new SdJwtVerifier(verificationOptions);

        // Act
        var result = verifier.TryVerifyPresentation(
            finalPresentationString,
            issuerSigningKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
    }

    [Fact]
    public void CompleteKeyBindingWorkflow_RequireKeyBindingButNotPresent_FailsVerification()
    {
        // Arrange
        var issuerSigningKey = new byte[32];
        RandomNumberGenerator.Fill(issuerSigningKey);

        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

        var issuer = new SdJwtIssuer();
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            issuerSigningKey,
            HashAlgorithm.Sha256,
            SignatureAlgorithm.HS256,
            holderPublicKey);

        var presenter = new SdJwtPresenter();
        var presentation = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationString = presenter.FormatPresentation(presentation);

        var verificationOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true  // Key binding required but not provided
        };
        var verifier = new SdJwtVerifier(verificationOptions);

        // Act
        var result = verifier.TryVerifyPresentation(
            presentationString,
            issuerSigningKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
    }

    [Fact]
    public void CompleteKeyBindingWorkflow_WithoutCnfClaim_FailsVerification()
    {
        // Arrange - Create SD-JWT without cnf claim
        var issuerSigningKey = new byte[32];
        RandomNumberGenerator.Fill(issuerSigningKey);

        using var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderPrivateKey = holderEcdsa.ExportECPrivateKey();

        var issuer = new SdJwtIssuer();
        var claims = new Dictionary<string, object> { { "sub", "user123" } };
        var sdJwt = issuer.CreateSdJwt(
            claims,
            Array.Empty<string>(),
            issuerSigningKey,
            HashAlgorithm.Sha256);  // No holder public key provided

        var presenter = new SdJwtPresenter();
        var presentationWithoutKb = presenter.CreatePresentationWithAllClaims(sdJwt);
        var presentationStringWithoutKb = presenter.FormatPresentation(presentationWithoutKb);

        using var sha256 = SHA256.Create();
        var sdJwtHashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(presentationStringWithoutKb));
        var sdJwtHash = Base64UrlEncoder.Encode(sdJwtHashBytes);

        // Create key binding JWT anyway
        var keyBindingGenerator = new KeyBindingGenerator();
        var keyBindingJwt = keyBindingGenerator.CreateKeyBindingJwt(
            holderPrivateKey,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce123");

        var finalPresentation = presenter.CreatePresentationWithAllClaims(sdJwt, keyBindingJwt);
        var finalPresentationString = presenter.FormatPresentation(finalPresentation);

        var verificationOptions = new SdJwtVerificationOptions
        {
            RequireKeyBinding = true
        };
        var verifier = new SdJwtVerifier(verificationOptions);

        // Act
        var result = verifier.TryVerifyPresentation(
            finalPresentationString,
            issuerSigningKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
    }
}
