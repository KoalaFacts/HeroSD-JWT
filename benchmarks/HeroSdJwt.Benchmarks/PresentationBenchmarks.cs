using BenchmarkDotNet.Attributes;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using SdJwtHashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(launchCount: 1, warmupCount: 3, iterationCount: 10)]
public class PresentationBenchmarks
{
    private byte[] _hmacKey = null!;
    private SdJwt _sdJwt = null!;
    private ECDsa _holderKey = null!;
    private string _keyBindingJwt = null!;
    private string _sdJwtHash = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        _hmacKey = new byte[32];
        RandomNumberGenerator.Fill(_hmacKey);
        _holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Generate SD-JWT with many selectable claims
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["sub"] = "user-123",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };

        for (int i = 0; i < 50; i++)
        {
            claims[$"claim_{i}"] = $"value_{i}";
        }

        var builder = new SdJwtIssuerBuilder()
            .WithClaims(claims)
            .WithHashAlgorithm(SdJwtHashAlgorithm.Sha256)
            .MakeSelective([.. claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k))]);

        _sdJwt = builder.SignWithHmac(_hmacKey).Build();

        // Pre-generate key binding JWT for benchmarking
        var presentation = _sdJwt.ToPresentation("claim_0");
        // Calculate SD-JWT hash (SHA-256 of ASCII presentation)
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(presentation));
        // Base64Url encode (base64 with URL-safe characters and no padding)
        _sdJwtHash = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        var kbGenerator = new KeyBindingGenerator();
        var holderPrivateKeyBytes = _holderKey.ExportECPrivateKey();
        _keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
            holderPrivateKeyBytes,
            _sdJwtHash,
            "https://verifier.example.com",
            "nonce-123");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _holderKey.Dispose();
    }

    [Benchmark]
    public string CreatePresentationFewClaims()
    {
        // Disclose only 5 claims
        return _sdJwt.ToPresentation("claim_0", "claim_1", "claim_2", "claim_3", "claim_4");
    }

    [Benchmark]
    public string CreatePresentationManyClaims()
    {
        // Disclose 25 claims
        string[] claimsToDisclose = [.. Enumerable.Range(0, 25).Select(i => $"claim_{i}")];
        return _sdJwt.ToPresentation(claimsToDisclose);
    }

    [Benchmark]
    public string CreatePresentationAllClaims()
    {
        // Disclose all 50 claims
        return _sdJwt.ToPresentationWithAllClaims();
    }

    [Benchmark]
    public string CreatePresentationWithKeyBinding()
    {
        // Disclose 5 claims with key binding
        return _sdJwt.ToPresentationWithKeyBinding(
            _keyBindingJwt,
            "claim_0", "claim_1", "claim_2", "claim_3", "claim_4");
    }
}
