using HeroSdJwt.Extensions;
using HeroSdJwt.Models;
using System.Diagnostics.Tracing;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Reconstructing verified claims must release parser-owned buffers without
/// invalidating the returned, independently owned JsonElement.
/// </summary>
public sealed class ReconstructionJsonDocumentLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_ReturnPooledJsonBuffers_AfterReconstructingDisclosedClaims(bool reconstructObject)
    {
        // Prepare immutable input before observing rents. Only allocations
        // performed by the reconstruction API are part of this ownership test.
        var result = new VerificationResult(new Dictionary<string, JsonElement>
        {
            ["degrees[0]"] = JsonSerializer.SerializeToElement("PhD"),
            ["address.street"] = JsonSerializer.SerializeToElement("Main St")
        });

        using var poolEvents = new CurrentThreadPoolEvents();
        if (reconstructObject)
        {
            var reconstructed = result.GetDisclosedObject("address");
            Assert.NotNull(reconstructed);
            Assert.Equal("Main St", reconstructed.Value.GetProperty("street").GetString());
        }
        else
        {
            var reconstructed = result.GetDisclosedArray("degrees");
            Assert.NotNull(reconstructed);
            Assert.Equal("PhD", reconstructed.Value[0].GetString());
        }

        // JsonDocument.Parse(string) rents buffers. A clone must remain usable,
        // while the temporary source document returns every rented buffer.
        Assert.True(poolEvents.Rented > 0, "Expected JSON reconstruction to rent pooled buffers.");
        Assert.Equal(poolEvents.Rented, poolEvents.Returned);
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
}
