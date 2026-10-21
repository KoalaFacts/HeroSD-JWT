using System.Diagnostics;
using System.Threading.Channels;

namespace HeroSdJwt.Tests.Load;

internal sealed record LoadScenario(string Name, LoadSchedule Schedule, Func<long, CancellationToken, ValueTask<bool>> Operation);

/// <summary>
/// Test-only open-model runner. Worker count, queued work, samples and diagnostic text are bounded.
/// Cancellation is cooperative; all workers finish before the caller can dispose workload resources.
/// </summary>
internal static class BoundedLoadRunner
{
    internal static async Task<LoadResult[]> RunAsync(LoadScenario[] scenarios, CancellationToken cancellationToken,
        int concurrency = 64, int queueCapacity = 256)
    {
        ArgumentNullException.ThrowIfNull(scenarios);
        if (concurrency is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(concurrency));
        }
        if (queueCapacity is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(queueCapacity));
        }
        if (scenarios.Length is < 1 or > 16 || scenarios.Any(s => s is null ||
            string.IsNullOrWhiteSpace(s.Name) || s.Schedule is null || s.Operation is null) ||
            scenarios.Select(s => s.Name).Distinct(StringComparer.Ordinal).Count() != scenarios.Length)
        {
            throw new ArgumentException("Provide 1–16 valid, uniquely named scenarios.", nameof(scenarios));
        }

        cancellationToken.ThrowIfCancellationRequested();
        long start = Stopwatch.GetTimestamp();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var runs = scenarios.Select(scenario => RunScenarioAsync(scenario, start, concurrency, queueCapacity, cancellation)).ToArray();
        return await Task.WhenAll(runs);
    }

    private static async Task<LoadResult> RunScenarioAsync(LoadScenario scenario, long start, int concurrency,
        int queueCapacity, CancellationTokenSource cancellation)
    {
        var token = cancellation.Token;
        var statistics = new LoadStatistics(Math.Max(1, scenario.Schedule.RequestCount));
        var queue = Channel.CreateBounded<Arrival>(new BoundedChannelOptions(queueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
            SingleReader = concurrency == 1,
            AllowSynchronousContinuations = false
        });
        var workers = Enumerable.Range(0, concurrency).Select(_ => Task.Run(async () =>
        {
            await foreach (var arrival in queue.Reader.ReadAllAsync(token))
            {
                token.ThrowIfCancellationRequested();
                bool success;
                string? error = null;
                try
                {
                    success = await scenario.Operation(arrival.Id, token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    success = false;
                    error = $"{exception.GetType().Name}: {exception.Message}";
                }
                statistics.Record(success, Stopwatch.GetElapsedTime(start) - arrival.Offset,
                    error ?? (success ? null : "Workload returned a failed result."));
            }
        }, CancellationToken.None)).ToArray();

        try
        {
            long id = 0;
            foreach (var offset in scenario.Schedule.Arrivals())
            {
                await DelayUntilAsync(start, offset, token);
                // Never wait for capacity: doing so would silently lower the offered arrival rate.
                if (!queue.Writer.TryWrite(new Arrival(++id, offset)))
                {
                    statistics.Reject(1);
                }
            }
            await DelayUntilAsync(start, scenario.Schedule.Duration, token);
        }
        catch
        {
            await cancellation.CancelAsync();
            throw;
        }
        finally
        {
            queue.Writer.TryComplete();
            await Task.WhenAll(workers);
        }
        token.ThrowIfCancellationRequested();
        // Draining slow work extends elapsed time rather than inflating successful RPS.
        return statistics.Complete(scenario.Name, Stopwatch.GetElapsedTime(start));
    }

    private static async Task DelayUntilAsync(long start, TimeSpan offset, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        TimeSpan remaining;
        while ((remaining = offset - Stopwatch.GetElapsedTime(start)) > TimeSpan.Zero)
        {
            // Round up: submillisecond Task.Delay truncation otherwise becomes a busy loop.
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Ceiling(remaining.TotalMilliseconds)), token);
        }
    }

    private readonly record struct Arrival(long Id, TimeSpan Offset);
}
