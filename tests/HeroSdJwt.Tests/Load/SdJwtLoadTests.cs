using HeroSdJwt.Extensions;
using HeroSdJwt.Primitives;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Load;

/// <summary>
/// Manual load tests using the bounded BCL runner. Remove the relevant Skip to run in Release mode.
/// The short runner correctness tests do not establish these manual performance baselines.
/// </summary>
public class SdJwtLoadTests(ITestOutputHelper output)
{
    private static LoadSchedule TenSeconds(int rate) => new(new LoadStage(rate, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10)));

    [Fact(Skip = "Load test - run manually when needed")]
    public async Task IssuanceLoadTest_HandlesHighConcurrency()
    {
        var stats = await RunIssuanceAsync(TenSeconds(100), TestContext.Current.CancellationToken);
        CheckHarness(stats);
        Assert.True(stats.RequestsPerSecond > 50, $"Expected RPS > 50, got {stats.RequestsPerSecond}");
        Assert.True(stats.P99Milliseconds < 100, $"Expected P99 < 100ms, got {stats.P99Milliseconds}ms");
    }

    [Fact(Skip = "Load test - run manually when needed")]
    public async Task VerificationLoadTest_HandlesHighThroughput()
    {
        var stats = await RunVerificationAsync(TenSeconds(200), TestContext.Current.CancellationToken);
        CheckHarness(stats);
        Assert.True(stats.RequestsPerSecond > 100, $"Expected RPS > 100, got {stats.RequestsPerSecond}");
        Assert.True(stats.P99Milliseconds < 50, $"Expected P99 < 50ms, got {stats.P99Milliseconds}ms");
        Assert.True(stats.FailureCount == 0, $"Expected 0 failures, got {stats.FailureCount}");
    }

    [Fact(Skip = "Load test - run manually when needed")]
    public async Task KeyBindingLoadTest_HandlesCryptographicLoad()
    {
        var stats = await RunKeyBindingAsync(TenSeconds(50), TestContext.Current.CancellationToken);
        CheckHarness(stats);
        Assert.True(stats.RequestsPerSecond > 25, $"Expected RPS > 25, got {stats.RequestsPerSecond}");
        Assert.True(stats.P99Milliseconds < 200, $"Expected P99 < 200ms, got {stats.P99Milliseconds}ms");
    }

    [Fact(Skip = "Load test - run manually when needed")]
    public async Task MixedScenarioLoadTest_SimulatesRealisticUsage()
    {
        var results = await RunMixedAsync(TenSeconds(50), TenSeconds(100), TestContext.Current.CancellationToken);
        var issuance = results.Single(s => s.Name == "issuance");
        var verification = results.Single(s => s.Name == "verification");
        CheckHarness(issuance);
        CheckHarness(verification);
        Assert.True(issuance.RequestsPerSecond > 30, $"Expected issuance RPS > 30, got {issuance.RequestsPerSecond}");
        Assert.True(verification.RequestsPerSecond > 40, $"Expected verification RPS > 40, got {verification.RequestsPerSecond}");
    }

    [Fact(Skip = "Load test - run manually when needed")]
    public async Task StressTest_RampUpToBreakingPoint()
    {
        var schedule = new LoadSchedule([.. new[] { 10, 50, 100, 200 }.Select(rate =>
            new LoadStage(rate, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10), Ramp: true))]);
        var stats = await RunStressAsync(schedule, TestContext.Current.CancellationToken);
        CheckHarness(stats);
        Assert.True(stats.P99Milliseconds < 500, $"Expected P99 latency < 500ms under stress, got {stats.P99Milliseconds}ms");
        Assert.True(stats.FailureRate < 0.01, $"Expected fail rate < 1%, got {stats.FailureRate * 100:F2}%");
    }

    private void CheckHarness(LoadResult result)
    {
        output.WriteLine(result.ToString());
        Assert.True(result.SuccessCount > 0, "The workload must actually complete successful operations.");
        Assert.True(result.RejectedCount == 0, $"Runner capacity was exceeded: {result.RejectedCount} arrivals rejected.");
    }

    internal static async Task<LoadResult> RunIssuanceAsync(LoadSchedule schedule, CancellationToken token)
    {
        var issuer = TestHelpers.CreateIssuer();
        var key = RandomNumberGenerator.GetBytes(32);
        var scenario = new LoadScenario("sd_jwt_issuance", schedule, (id, _) =>
        {
            var claims = new Dictionary<string, object>
            {
                ["sub"] = $"user-{id}",
                ["email"] = $"user{id}@example.com",
                ["name"] = $"User {id}",
                ["role"] = "tester"
            };
            issuer.CreateSdJwt(claims, ["email", "name"], key, Primitives.HashAlgorithm.Sha256, SignatureAlgorithm.HS256);
            return ValueTask.FromResult(true);
        });
        return (await BoundedLoadRunner.RunAsync([scenario], token))[0];
    }

    internal static async Task<LoadResult> RunVerificationAsync(LoadSchedule schedule, CancellationToken token)
    {
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var key = RandomNumberGenerator.GetBytes(32);
        var presentations = new List<string>();
        for (int i = 0; i < 1000; i++)
        {
            token.ThrowIfCancellationRequested();
            var claims = new Dictionary<string, object>
            {
                ["sub"] = $"user-{i}",
                ["email"] = $"user{i}@example.com",
                ["name"] = $"User {i}"
            };
            var sdJwt = issuer.CreateSdJwt(claims, ["email"], key, Primitives.HashAlgorithm.Sha256, SignatureAlgorithm.HS256);
            presentations.Add(sdJwt.ToPresentation("email"));
        }
        var scenario = new LoadScenario("sd_jwt_verification", schedule, (id, _) =>
            ValueTask.FromResult(verifier.TryVerifyPresentation(presentations[(int)(id % presentations.Count)], key).IsValid));
        return (await BoundedLoadRunner.RunAsync([scenario], token))[0];
    }

    internal static async Task<LoadResult> RunKeyBindingAsync(LoadSchedule schedule, CancellationToken token)
    {
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var issuerKey = RandomNumberGenerator.GetBytes(32);
        var holderKeys = new List<ECDsa>();
        try
        {
            for (int i = 0; i < 10; i++)
            {
                token.ThrowIfCancellationRequested();
                holderKeys.Add(ECDsa.Create(ECCurve.NamedCurves.nistP256));
            }
            var scenario = new LoadScenario("sd_jwt_key_binding", schedule, (id, _) =>
            {
                var holderKey = holderKeys[(int)(id % holderKeys.Count)];
                byte[] holderPublicKey;
                // ECDsa instance methods are not promised thread-safe; keep each export in the measured operation.
                lock (holderKey)
                {
                    holderPublicKey = holderKey.ExportSubjectPublicKeyInfo();
                }
                var claims = new Dictionary<string, object>
                {
                    ["sub"] = $"user-{id}",
                    ["email"] = $"user{id}@example.com"
                };
                var sdJwt = issuer.CreateSdJwt(claims, ["email"], issuerKey, Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256, holderPublicKey);
                var presentation = sdJwt.ToPresentation("email");
                return ValueTask.FromResult(verifier.TryVerifyPresentation(presentation, issuerKey).IsValid);
            });
            return (await BoundedLoadRunner.RunAsync([scenario], token))[0];
        }
        finally
        {
            foreach (var key in holderKeys)
            {
                key.Dispose();
            }
        }
    }

    internal static Task<LoadResult[]> RunMixedAsync(LoadSchedule issuanceSchedule, LoadSchedule verificationSchedule, CancellationToken token)
        => BoundedLoadRunner.RunAsync(CreateMixedScenarios(issuanceSchedule, verificationSchedule), token);

    internal static LoadScenario[] CreateMixedScenarios(LoadSchedule issuanceSchedule, LoadSchedule verificationSchedule)
    {
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var key = RandomNumberGenerator.GetBytes(32);
        // Each issuance adds at most one item; the finite arrival budget bounds retained payloads.
        var presentations = new ConcurrentBag<string>();
        var issuance = new LoadScenario("issuance", issuanceSchedule, (id, _) =>
        {
            var claims = new Dictionary<string, object>
            {
                ["sub"] = $"user-{id}",
                ["email"] = $"user{id}@example.com",
                ["name"] = $"User {id}",
                ["department"] = "Engineering"
            };
            var sdJwt = issuer.CreateSdJwt(claims, ["email", "department"], key, Primitives.HashAlgorithm.Sha256, SignatureAlgorithm.HS256);
            presentations.Add(sdJwt.ToPresentation("email", "department"));
            return ValueTask.FromResult(true);
        });
        var verification = new LoadScenario("verification", verificationSchedule, (_, _) =>
            ValueTask.FromResult(presentations.TryTake(out var presentation) && verifier.TryVerifyPresentation(presentation, key).IsValid));
        return [issuance, verification];
    }

    internal static async Task<LoadResult> RunStressAsync(LoadSchedule schedule, CancellationToken token)
    {
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var key = RandomNumberGenerator.GetBytes(32);
        var scenario = new LoadScenario("stress_test", schedule, (id, _) =>
        {
            var claims = new Dictionary<string, object>
            {
                ["sub"] = $"user-{id}",
                ["email"] = $"user{id}@example.com"
            };
            var sdJwt = issuer.CreateSdJwt(claims, ["email"], key, Primitives.HashAlgorithm.Sha256, SignatureAlgorithm.HS256);
            return ValueTask.FromResult(verifier.TryVerifyPresentation(sdJwt.ToPresentation("email"), key).IsValid);
        });
        return (await BoundedLoadRunner.RunAsync([scenario], token))[0];
    }
}
