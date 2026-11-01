using HeroSdJwt.AspNetCore.Authentication;
using HeroSdJwt.Encoding;
using HeroSdJwt.Models;
using HeroSdJwt.Verification;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Diagnostics.Tracing;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace HeroSdJwt.AspNetCore.Tests.Integration;

/// <summary>
/// ASP.NET claim projection must release JsonDocument-owned pooled buffers
/// after converting verified JWT payload properties into independent claims.
/// </summary>
public sealed class AuthenticationPayloadDocumentLifetimeTests
{
    [Fact]
    public void Should_ReturnPooledJsonBuffers_AfterMappingAuthenticatedClaims()
    {
        // Exercise the handler's post-verification claim projection directly.
        // This isolates ownership from signature-verification allocations.
        var handler = new SdJwtAuthenticationHandler(
            new StaticOptionsMonitor(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            SdJwtVerifierBuilder.Create().Build());

        var payload = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"sub":"holder-1","name":"Alice"}""");
        var presentation = $"e30.{payload}.e30~";
        var verified = new VerificationResult(new Dictionary<string, JsonElement>());
        var projection = typeof(SdJwtAuthenticationHandler).GetMethod(
            "MapAllClaimsToPrincipal",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(projection);

        // JsonDocument.Parse(string) rents pooled UTF-8/metadata buffers.
        // The previous code discarded the document without disposing it.
        using var poolEvents = new CurrentThreadPoolEvents();
        var mapped = (List<Claim>)projection.Invoke(handler, [presentation, verified])!;

        Assert.Contains(mapped, claim => claim.Type == "name" && claim.Value == "Alice");
        Assert.Contains(mapped, claim => claim.Type == "sub" && claim.Value == "holder-1");
        Assert.True(poolEvents.Rented > 0, "Expected JsonDocument to rent pooled buffers.");
        Assert.Equal(poolEvents.Rented, poolEvents.Returned);
    }


    [Fact]
    public void Should_AvoidDisclosureProportionalAllocations_WhenMappingAuthenticatedClaims()
    {
        // Claim projection runs after verification. Only the issuer JWT payload
        // and verified claims are needed; disclosure strings must not be copied.
        var handler = new SdJwtAuthenticationHandler(
            new StaticOptionsMonitor(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            SdJwtVerifierBuilder.Create().Build());
        var payload = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"sub":"holder-1","name":"Alice"}""");
        var value = new string('a', 256);
        var disclosures = Enumerable.Range(0, 100)
            .Select(index => Base64UrlEncoder.Encode($"[\"salt-{index}\",\"claim-{index}\",\"{value}\"]"));
        var presentation = $"e30.{payload}.e30~{string.Join("~", disclosures)}~";
        Assert.True(presentation.Length < 64 * 1024);

        var verified = new VerificationResult(new Dictionary<string, JsonElement>());
        var projection = typeof(SdJwtAuthenticationHandler).GetMethod(
            "MapAllClaimsToPrincipal",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(projection);

        // Warm reflection, JIT, JSON parser and pooling before measuring the
        // current thread. A Split('~') of 100 long disclosures allocates >75 KiB.
        for (var i = 0; i < 4; i++)
        {
            _ = projection.Invoke(handler, [presentation, verified]);
        }

        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var mapped = (List<Claim>)projection.Invoke(handler, [presentation, verified])!;
        var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

        Assert.Contains(mapped, claim => claim.Type == "name" && claim.Value == "Alice");
        Assert.Contains(mapped, claim => claim.Type == "sub" && claim.Value == "holder-1");
        Assert.True(allocated < 16 * 1024,
            $"Claim projection allocated {allocated} bytes for 100 disclosures; expected under 16 KiB.");
    }

    private sealed class CurrentThreadPoolEvents : EventListener
    {
        private readonly int _threadId = Environment.CurrentManagedThreadId;

        public int Rented { get; private set; }

        public int Returned { get; private set; }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name == "System.Buffers.ArrayPoolEventSource")
            {
                EnableEvents(eventSource, EventLevel.Verbose);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (Environment.CurrentManagedThreadId != _threadId)
            {
                return;
            }

            if (eventData.EventName == "BufferRented")
            {
                Rented++;
            }
            else if (eventData.EventName == "BufferReturned")
            {
                Returned++;
            }
        }
    }

    private sealed class StaticOptionsMonitor : IOptionsMonitor<SdJwtAuthenticationOptions>
    {
        public SdJwtAuthenticationOptions CurrentValue { get; } = new();

        public SdJwtAuthenticationOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<SdJwtAuthenticationOptions, string?> listener) => null;
    }
}
