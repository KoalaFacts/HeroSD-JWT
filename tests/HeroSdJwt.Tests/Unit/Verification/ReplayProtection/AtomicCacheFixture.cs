using HeroSdJwt.AspNetCore.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

// A deterministic contract fixture, not a deployable distributed backend. The lock
// models one backend's atomic operation; no production adapter uses a process lock.
internal sealed class AtomicCacheFixture(int concurrentAdmissions = 1) : IAtomicDistributedCache
{
#if NET9_0_OR_GREATER
    private readonly Lock _sync = new();
#else
    private readonly object _sync = new();
#endif
    private readonly Dictionary<string, (byte[] Value, TimeSpan Expires)> _entries = [];
    private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TimeSpan _now;
    private int _arrivals;
    public Exception? AdmissionFailure { get; init; }
    public bool WaitForCancellation { get; init; }

    public void Advance(TimeSpan elapsed)
    {
        lock (_sync)
        {
            _now += elapsed;
        }
    }

    public async Task<bool> TryAddAsync(string key, byte[] value, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (WaitForCancellation)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        if (AdmissionFailure is not null)
        {
            throw AdmissionFailure;
        }
        if (Interlocked.Increment(ref _arrivals) >= concurrentAdmissions)
        {
            _gate.TrySetResult();
        }
        await _gate.Task.WaitAsync(cancellationToken);
        lock (_sync)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_entries.TryGetValue(key, out var current) && current.Expires > _now)
            {
                return false;
            }
            _entries[key] = (value, _now + ttl);
            return true;
        }
    }

    public byte[]? Get(string key)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(key, out var current) && current.Expires > _now ? current.Value : null;
        }
    }
    public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        return Task.FromResult(Get(key));
    }
    public void Remove(string key)
    {
        lock (_sync)
        {
            _entries.Remove(key);
        }
    }
    public Task RemoveAsync(string key, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        Remove(key);
        return Task.CompletedTask;
    }

    // Independent writes/refreshes must never be used for replay admission.
    public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw new NotSupportedException();
    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => throw new NotSupportedException();
    public void Refresh(string key) => throw new NotSupportedException();
    public Task RefreshAsync(string key, CancellationToken token = default) => throw new NotSupportedException();
}
