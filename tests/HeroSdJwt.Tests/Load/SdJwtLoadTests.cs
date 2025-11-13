using System.Security.Cryptography;
using HeroSdJwt.Extensions;
using HeroSdJwt.Primitives;
using NBomber.CSharp;

namespace HeroSdJwt.Tests.Load;

/// <summary>
/// Load tests using NBomber to simulate realistic usage patterns and identify performance bottlenecks.
/// These tests are skipped by default and should be run manually when needed.
/// </summary>
/// <remarks>
/// To run load tests manually, remove the Skip attribute and run:
/// <code>
/// dotnet test --filter "FullyQualifiedName~Load" --configuration Release
/// </code>
/// </remarks>
public class SdJwtLoadTests
{
    /// <summary>
    /// Load test for SD-JWT issuance - simulates creating many SD-JWTs concurrently.
    /// Tests the scalability of the issuance process under high load.
    /// </summary>
    [Fact(Skip = "Load test - run manually when needed")]
    public void IssuanceLoadTest_HandlesHighConcurrency()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var scenario = Scenario.Create("sd_jwt_issuance", async context =>
        {
            var claims = new Dictionary<string, object>
            {
                ["sub"] = $"user-{context.ScenarioInfo.InstanceId}-{context.InvocationNumber}",
                ["email"] = $"user{context.InvocationNumber}@example.com",
                ["name"] = $"User {context.InvocationNumber}",
                ["role"] = "tester"
            };

            try
            {
                var sdJwt = issuer.CreateSdJwt(
                    claims,
                    new[] { "email", "name" },
                    key,
                    HeroSdJwt.Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256);

                return Response.Ok(sdJwt);
            }
            catch (Exception ex)
            {
                return Response.Fail<object>(ex.Message);
            }
        })
        .WithoutWarmUp()
        .WithLoadSimulations(
            Simulation.Inject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10))
        );

        // Act
        var stats = NBomberRunner
            .RegisterScenarios(scenario)
            .Run();

        // Assert
        var scenarioStats = stats.ScenarioStats[0];
        Assert.True(scenarioStats.Ok.Request.RPS > 50,
            $"Expected RPS > 50, got {scenarioStats.Ok.Request.RPS}");
        Assert.True(scenarioStats.Ok.Latency.Percent99 < 100,
            $"Expected P99 < 100ms, got {scenarioStats.Ok.Latency.Percent99}ms");
    }

    /// <summary>
    /// Load test for SD-JWT verification - simulates verifying many presentations concurrently.
    /// Tests the scalability of the verification process under high load.
    /// </summary>
    [Fact(Skip = "Load test - run manually when needed")]
    public void VerificationLoadTest_HandlesHighThroughput()
    {
        // Arrange - Pre-generate SD-JWTs for verification
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var presentations = new List<string>();
        for (int i = 0; i < 1000; i++)
        {
            var claims = new Dictionary<string, object>
            {
                ["sub"] = $"user-{i}",
                ["email"] = $"user{i}@example.com",
                ["name"] = $"User {i}"
            };

            var sdJwt = issuer.CreateSdJwt(
                claims,
                new[] { "email" },
                key,
                HeroSdJwt.Primitives.HashAlgorithm.Sha256,
                SignatureAlgorithm.HS256);

            presentations.Add(sdJwt.ToPresentation("email"));
        }

        var scenario = Scenario.Create("sd_jwt_verification", async context =>
        {
            var presentation = presentations[(int)(context.InvocationNumber % presentations.Count)];

            try
            {
                var result = verifier.TryVerifyPresentation(presentation, key);

                return result.IsValid
                    ? Response.Ok(result)
                    : Response.Fail<object>("Verification failed");
            }
            catch (Exception ex)
            {
                return Response.Fail<object>(ex.Message);
            }
        })
        .WithoutWarmUp()
        .WithLoadSimulations(
            Simulation.Inject(rate: 200, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10))
        );

        // Act
        var stats = NBomberRunner
            .RegisterScenarios(scenario)
            .Run();

        // Assert
        var scenarioStats = stats.ScenarioStats[0];
        Assert.True(scenarioStats.Ok.Request.RPS > 100,
            $"Expected RPS > 100, got {scenarioStats.Ok.Request.RPS}");
        Assert.True(scenarioStats.Ok.Latency.Percent99 < 50,
            $"Expected P99 < 50ms, got {scenarioStats.Ok.Latency.Percent99}ms");
        Assert.True(scenarioStats.Fail.Request.Count == 0,
            $"Expected 0 failures, got {scenarioStats.Fail.Request.Count}");
    }

    /// <summary>
    /// Load test for key binding operations - simulates creating and verifying JWTs with key binding.
    /// Tests the performance of cryptographic operations under high load.
    /// </summary>
    [Fact(Skip = "Load test - run manually when needed")]
    public void KeyBindingLoadTest_HandlesCryptographicLoad()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var issuerKey = new byte[32];
        RandomNumberGenerator.Fill(issuerKey);

        // Pre-generate holder key pairs for reuse
        var holderKeys = new List<ECDsa>();
        for (int i = 0; i < 10; i++)
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            holderKeys.Add(ecdsa);
        }

        var scenario = Scenario.Create("sd_jwt_key_binding", async context =>
        {
            try
            {
                var holderKey = holderKeys[(int)(context.InvocationNumber % holderKeys.Count)];
                var holderPublicKey = holderKey.ExportSubjectPublicKeyInfo();

                var claims = new Dictionary<string, object>
                {
                    ["sub"] = $"user-{context.InvocationNumber}",
                    ["email"] = $"user{context.InvocationNumber}@example.com"
                };

                var sdJwt = issuer.CreateSdJwt(
                    claims,
                    new[] { "email" },
                    issuerKey,
                    HeroSdJwt.Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256,
                    holderPublicKey);

                var presentation = sdJwt.ToPresentation("email");
                var result = verifier.TryVerifyPresentation(presentation, issuerKey);

                return result.IsValid
                    ? Response.Ok(result)
                    : Response.Fail<object>("Verification failed");
            }
            catch (Exception ex)
            {
                return Response.Fail<object>(ex.Message);
            }
        })
        .WithoutWarmUp()
        .WithLoadSimulations(
            Simulation.Inject(rate: 50, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10))
        );

        // Act
        var stats = NBomberRunner
            .RegisterScenarios(scenario)
            .Run();

        // Assert - Cleanup
        foreach (var key in holderKeys)
        {
            key.Dispose();
        }

        var scenarioStats = stats.ScenarioStats[0];
        Assert.True(scenarioStats.Ok.Request.RPS > 25,
            $"Expected RPS > 25, got {scenarioStats.Ok.Request.RPS}");
        Assert.True(scenarioStats.Ok.Latency.Percent99 < 200,
            $"Expected P99 < 200ms, got {scenarioStats.Ok.Latency.Percent99}ms");
    }

    /// <summary>
    /// Mixed scenario load test - simulates realistic usage with issuance and verification.
    /// Tests the system under a realistic workload pattern.
    /// </summary>
    [Fact(Skip = "Load test - run manually when needed")]
    public void MixedScenarioLoadTest_SimulatesRealisticUsage()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var presentations = new System.Collections.Concurrent.ConcurrentBag<string>();

        var issuanceScenario = Scenario.Create("issuance", async context =>
        {
            try
            {
                var claims = new Dictionary<string, object>
                {
                    ["sub"] = $"user-{context.InvocationNumber}",
                    ["email"] = $"user{context.InvocationNumber}@example.com",
                    ["name"] = $"User {context.InvocationNumber}",
                    ["department"] = "Engineering"
                };

                var sdJwt = issuer.CreateSdJwt(
                    claims,
                    new[] { "email", "department" },
                    key,
                    HeroSdJwt.Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256);

                var presentation = sdJwt.ToPresentation("email", "department");
                presentations.Add(presentation);

                return Response.Ok();
            }
            catch (Exception ex)
            {
                return Response.Fail<object>(ex.Message);
            }
        })
        .WithoutWarmUp()
        .WithLoadSimulations(
            Simulation.Inject(rate: 50, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10))
        );

        var verificationScenario = Scenario.Create("verification", async context =>
        {
            try
            {
                if (presentations.TryTake(out var presentation))
                {
                    var result = verifier.TryVerifyPresentation(presentation, key);
                    return result.IsValid
                        ? Response.Ok()
                        : Response.Fail<object>("Verification failed");
                }

                return Response.Fail<object>("No presentations available");
            }
            catch (Exception ex)
            {
                return Response.Fail<object>(ex.Message);
            }
        })
        .WithoutWarmUp()
        .WithLoadSimulations(
            Simulation.Inject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10))
        );

        // Act
        var stats = NBomberRunner
            .RegisterScenarios(issuanceScenario, verificationScenario)
            .Run();

        // Assert
        var issuanceStats = stats.ScenarioStats.First(s => s.ScenarioName == "issuance");
        var verificationStats = stats.ScenarioStats.First(s => s.ScenarioName == "verification");

        Assert.True(issuanceStats.Ok.Request.RPS > 30,
            $"Expected issuance RPS > 30, got {issuanceStats.Ok.Request.RPS}");
        Assert.True(verificationStats.Ok.Request.RPS > 60,
            $"Expected verification RPS > 60, got {verificationStats.Ok.Request.RPS}");
    }

    /// <summary>
    /// Stress test with ramp-up - gradually increases load to find breaking point.
    /// Tests system behavior under increasing stress.
    /// </summary>
    [Fact(Skip = "Load test - run manually when needed")]
    public void StressTest_RampUpToBreakingPoint()
    {
        // Arrange
        var issuer = TestHelpers.CreateIssuer();
        var verifier = TestHelpers.CreateVerifier();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var scenario = Scenario.Create("stress_test", async context =>
        {
            try
            {
                var claims = new Dictionary<string, object>
                {
                    ["sub"] = $"user-{context.InvocationNumber}",
                    ["email"] = $"user{context.InvocationNumber}@example.com"
                };

                var sdJwt = issuer.CreateSdJwt(
                    claims,
                    new[] { "email" },
                    key,
                    HeroSdJwt.Primitives.HashAlgorithm.Sha256,
                    SignatureAlgorithm.HS256);

                var presentation = sdJwt.ToPresentation("email");
                var result = verifier.TryVerifyPresentation(presentation, key);

                return result.IsValid
                    ? Response.Ok()
                    : Response.Fail<object>("Verification failed");
            }
            catch (Exception ex)
            {
                return Response.Fail<object>(ex.Message);
            }
        })
        .WithoutWarmUp()
        .WithLoadSimulations(
            Simulation.RampingInject(rate: 10, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
            Simulation.RampingInject(rate: 50, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
            Simulation.RampingInject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
            Simulation.RampingInject(rate: 200, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10))
        );

        // Act
        var stats = NBomberRunner
            .RegisterScenarios(scenario)
            .Run();

        // Assert
        var scenarioStats = stats.ScenarioStats[0];

        // The test succeeds if the system handles the load without crashing
        // and maintains reasonable latency even under high load
        Assert.True(scenarioStats.Ok.Latency.Percent99 < 500,
            $"Expected P99 latency < 500ms under stress, got {scenarioStats.Ok.Latency.Percent99}ms");

        // Fail rate should be low even under stress
        var totalRequests = scenarioStats.Ok.Request.Count + scenarioStats.Fail.Request.Count;
        var failRate = totalRequests > 0 ? scenarioStats.Fail.Request.Count / (double)totalRequests : 0;
        Assert.True(failRate < 0.01, $"Expected fail rate < 1%, got {failRate * 100:F2}%");
    }
}
