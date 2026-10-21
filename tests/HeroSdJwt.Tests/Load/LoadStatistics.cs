namespace HeroSdJwt.Tests.Load;

/// <summary>Exact successful-request P99 with a prevalidated, finite sample budget.</summary>
internal sealed class LoadStatistics
{
#if NET9_0_OR_GREATER
    private readonly Lock _gate = new();
#else
    private readonly object _gate = new();
#endif
    private readonly double[] _latencies;
    private readonly List<string> _errors = [];
    private int _successCount;
    private int _failureCount;
    private int _rejectedCount;

    internal LoadStatistics(int capacity)
    {
        if (capacity < 1 || capacity > LoadSchedule.MAX_REQUESTS)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        _latencies = new double[capacity];
    }

    internal void Record(bool succeeded, TimeSpan latency, string? error = null)
    {
        lock (_gate)
        {
            EnsureCapacity(1);
            if (succeeded)
            {
                _latencies[_successCount++] = latency.TotalMilliseconds;
            }
            else
            {
                _failureCount++;
                if (error is not null && _errors.Count < 5)
                {
                    _errors.Add(error[..Math.Min(error.Length, 512)]);
                }
            }
        }
    }

    internal void Reject(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        lock (_gate)
        {
            EnsureCapacity(count);
            _failureCount += count;
            _rejectedCount += count;
        }
    }

    internal LoadResult Complete(string name, TimeSpan duration)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(duration, TimeSpan.Zero);
        lock (_gate)
        {
            Array.Sort(_latencies, 0, _successCount);
            double p99 = _successCount == 0 ? double.PositiveInfinity : _latencies[(int)Math.Ceiling(_successCount * 0.99) - 1];
            return new(name, _successCount, _failureCount, _rejectedCount, duration, p99, [.. _errors]);
        }
    }

    private void EnsureCapacity(int count)
    {
        if (count > _latencies.Length - _successCount - _failureCount)
        {
            throw new InvalidOperationException("The scheduled request budget was exceeded.");
        }
    }
}

internal sealed record LoadResult(string Name, int SuccessCount, int FailureCount, int RejectedCount,
    TimeSpan Duration, double P99Milliseconds, IReadOnlyList<string> Errors)
{
    internal double RequestsPerSecond => SuccessCount / Duration.TotalSeconds;
    internal double FailureRate => SuccessCount + FailureCount == 0 ? 1 : FailureCount / (double)(SuccessCount + FailureCount);
    public override string ToString() => $"{Name}: successful={SuccessCount}, failed={FailureCount}, capacity-rejected={RejectedCount}, " +
        $"duration={Duration.TotalSeconds:F3}s, successful RPS={RequestsPerSecond:F2}, successful P99={P99Milliseconds:F3}ms; " + string.Join("; ", Errors);
}
