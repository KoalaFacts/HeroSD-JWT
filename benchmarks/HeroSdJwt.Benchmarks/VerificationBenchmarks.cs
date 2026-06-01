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
    private byte[] _hmacKey = null!;
    private RSA _rsa = null!;
    private ECDsa _ecdsa = null!;
    private ECDsa _holderKey = null!;

    private SdJwt _sdJwtHmac = null!;
    private SdJwtVerifier _verifier = null!;
    private SdJwtVerifier _verifierWithKeyBinding = null!;

    private string _presentation = null!;
    private string _presentationWithKeyBinding = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        _hmacKey = new byte[32];
        RandomNumberGenerator.Fill(_hmacKey);

        _rsa = RSA.Create(2048);
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

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

        _sdJwtHmac = builder.SignWithHmac(_hmacKey).Build();
        var rsaPrivateKey = _rsa.ExportPkcs8PrivateKey();
        _ = builder.SignWithRsa(rsaPrivateKey).Build();

        // Create presentations
        _presentation = _sdJwtHmac.ToPresentation("email", "name");

        // Create presentation with key binding
        var holderPublicKey = _holderKey.ExportSubjectPublicKeyInfo();

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
        var holderPrivateKeyBytes = _holderKey.ExportECPrivateKey();
        var keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
            holderPrivateKeyBytes,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce-123");

        _presentationWithKeyBinding = sdJwtWithKeyBinding.ToPresentationWithKeyBinding(
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
            ExpectedIssuer = "https://issuer.example.com",
            // The presentation is HS256 (HMAC); the verifier defaults to Asymmetric,
            // so without this the throwing VerifyPresentation raises an alg/key-confusion
            // error every iteration (no statistics -> breaks the benchmark report).
            ExpectedKeyType = HeroSdJwt.Primitives.VerificationKeyType.Symmetric
        };

        _verifier = new SdJwtVerifier(
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

        _verifierWithKeyBinding = new SdJwtVerifier(
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
        _rsa.Dispose();
        _ecdsa.Dispose();
        _holderKey.Dispose();
    }

    [Benchmark]
    public VerificationResult VerifyWithoutKeyBinding()
    {
        return _verifier.VerifyPresentation(_presentation, _hmacKey);
    }

    [Benchmark]
    public VerificationResult VerifyWithKeyBinding()
    {
        // Export RSA public key for verification
        var rsaPublicKey = _rsa.ExportSubjectPublicKeyInfo();
        return _verifierWithKeyBinding.VerifyPresentation(_presentationWithKeyBinding, rsaPublicKey);
    }

    [Benchmark]
    public VerificationResult TryVerifyWithoutKeyBinding()
    {
        return _verifier.TryVerifyPresentation(_presentation, _hmacKey);
    }
}
