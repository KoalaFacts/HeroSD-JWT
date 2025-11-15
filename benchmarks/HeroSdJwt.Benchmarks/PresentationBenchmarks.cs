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
    private byte[] hmacKey = null!;
    private SdJwt sdJwt = null!;
    private ECDsa holderKey = null!;
    private string keyBindingJwt = null!;
    private string sdJwtHash = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Generate keys
        hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);
        holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

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
            .MakeSelective(claims.Keys.Where(k => !Constants.ReservedClaims.Contains(k)).ToArray());

        sdJwt = builder.SignWithHmac(hmacKey).Build();

        // Pre-generate key binding JWT for benchmarking
        var presentation = sdJwt.ToPresentation("claim_0");
        // Calculate SD-JWT hash (SHA-256 of ASCII presentation)
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(presentation));
        // Base64Url encode (base64 with URL-safe characters and no padding)
        sdJwtHash = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        var kbGenerator = new KeyBindingGenerator();
        var holderPrivateKeyBytes = holderKey.ExportECPrivateKey();
        keyBindingJwt = kbGenerator.CreateKeyBindingJwt(
            holderPrivateKeyBytes,
            sdJwtHash,
            "https://verifier.example.com",
            "nonce-123");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        holderKey.Dispose();
    }

    [Benchmark]
    public string CreatePresentationFewClaims()
    {
        // Disclose only 5 claims
        return sdJwt.ToPresentation("claim_0", "claim_1", "claim_2", "claim_3", "claim_4");
    }

    [Benchmark]
    public string CreatePresentationManyClaims()
    {
        // Disclose 25 claims
        var claimsToDisclose = Enumerable.Range(0, 25).Select(i => $"claim_{i}").ToArray();
        return sdJwt.ToPresentation(claimsToDisclose);
    }

    [Benchmark]
    public string CreatePresentationAllClaims()
    {
        // Disclose all 50 claims
        return sdJwt.ToPresentationWithAllClaims();
    }

    [Benchmark]
    public string CreatePresentationWithKeyBinding()
    {
        // Disclose 5 claims with key binding
        return sdJwt.ToPresentationWithKeyBinding(
            keyBindingJwt,
            "claim_0", "claim_1", "claim_2", "claim_3", "claim_4");
    }
}
