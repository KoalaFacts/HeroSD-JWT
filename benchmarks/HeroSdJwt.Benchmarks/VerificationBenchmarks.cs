using BenchmarkDotNet.Attributes;
using HeroSdJwt.Cryptography;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using HeroSdJwt.Verification;
using System.Buffers.Text;
using System.Security.Cryptography;
using SdJwtHashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(launchCount: 1, warmupCount: 3, iterationCount: 10)]
public class VerificationBenchmarks
{
    private byte[] hmacKey = null!;
    private RSA rsa = null!;
    private ECDsa ecdsa = null!;
    private ECDsa holderKey = null!;

    private SdJwt sdJwtHmac = null!;
    private SdJwt sdJwtRsa = null!;
    private SdJwtVerifier verifier = null!;
    private SdJwtVerifier verifierWithKeyBinding = null!;

    private string presentation = null!;
    private string presentationWithKeyBinding = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        rsa = RSA.Create(2048);
        ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Generate SD-JWTs
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["sub"] = "user-123",
            ["aud"] = "https://verifier.example.com",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            ["email"] = "alice@example.com",
            ["name"] = "Alice Smith",
            ["birthdate"] = "1990-01-01",
            ["address"] = new Dictionary<string, object>
            {
                ["street"] = "123 Main St",
                ["city"] = "Anytown",
                ["country"] = "US"
            }
        };

        var builder = new SdJwtIssuerBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective("email", "name", "birthdate");

        sdJwtHmac = builder.SignWithHmac(hmacKey).Build();
        var rsaPrivateKey = rsa.ExportPkcs8PrivateKey();
        sdJwtRsa = builder.SignWithRsa(rsaPrivateKey).Build();

        // Create presentations
        presentation = sdJwtHmac.ToPresentation("email", "name");

        // Create presentation with key binding
        var holderPublicKey = holderKey.ExportSubjectPublicKeyInfo();

        var builderWithKeyBinding = new SdJwtIssuerBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .WithKeyBinding(holderPublicKey)
            .MakeSelective("email", "name", "birthdate");

        var sdJwtWithKeyBinding = builderWithKeyBinding.SignWithRsa(rsaPrivateKey).Build();

        // Generate key binding JWT
        var tempPresentation = sdJwtWithKeyBinding.ToPresentation("email", "name");
        // Calculate SD-JWT hash (SHA-256 of UTF-8 presentation)
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(tempPresentation));
        // Base64Url encode using built-in .NET API
        var sdJwtHash = Base64Url.EncodeToString(hashBytes);

        var kbGenerator = new KeyBindingGenerator();
        var holderPrivateKeyBytes = holderKey.ExportECPrivateKey();
        var keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
            holderPrivateKeyBytes,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce-123");

        presentationWithKeyBinding = sdJwtWithKeyBinding.ToPresentationWithKeyBinding(
            keyBindingJwt,
            "email", "name");

        // Create verifiers with required dependencies
        var ecPublicKeyConverter = new EcPublicKeyConverter();
        var signatureValidator = new SignatureValidator();
        var digestValidator = new DigestValidator();
        var keyBindingValidator = new KeyBindingValidator(TimeProvider.System);
        var claimValidator = new ClaimValidator();

        var verifierOptions = new SdJwtVerificationOptions
        {
            ExpectedIssuer = "https://issuer.example.com"
        };

        verifier = new SdJwtVerifier(
            verifierOptions,
            ecPublicKeyConverter,
            signatureValidator,
            digestValidator,
            keyBindingValidator,
            claimValidator);

        var verifierWithKbOptions = new SdJwtVerificationOptions
        {
            ExpectedIssuer = "https://issuer.example.com",
            ExpectedAudience = "https://verifier.example.com",
            ExpectedNonce = "nonce-123",
            RequireKeyBinding = true
        };

        verifierWithKeyBinding = new SdJwtVerifier(
            verifierWithKbOptions,
            ecPublicKeyConverter,
            signatureValidator,
            digestValidator,
            keyBindingValidator,
            claimValidator);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        rsa.Dispose();
        ecdsa.Dispose();
        holderKey.Dispose();
    }

    [Benchmark]
    public VerificationResult VerifyWithoutKeyBinding()
    {
        return verifier.VerifyPresentation(presentation, hmacKey);
    }

    [Benchmark]
    public VerificationResult VerifyWithKeyBinding()
    {
        // Export RSA public key for verification
        var rsaPublicKey = rsa.ExportSubjectPublicKeyInfo();
        return verifierWithKeyBinding.VerifyPresentation(presentationWithKeyBinding, rsaPublicKey);
    }

    [Benchmark]
    public VerificationResult TryVerifyWithoutKeyBinding()
    {
        return verifier.TryVerifyPresentation(presentation, hmacKey);
    }
}
