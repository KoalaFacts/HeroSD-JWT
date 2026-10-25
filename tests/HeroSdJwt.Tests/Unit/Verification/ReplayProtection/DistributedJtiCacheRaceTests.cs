using System.Collections.Concurrent;
using HeroSdJwt.AspNetCore.Verification.ReplayProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace HeroSdJwt.Tests.Unit.Verification.ReplayProtection;

public class DistributedJtiCacheRaceTests
{
    [Fact]
    public void CachePermittingReadWriteRace_IsRejectedBeforeAnyIo()
    {
        // Before the fix, 32 independent adapters all accepted the same identifier
        // with this backend. A generic cache is now rejected before its first read.
        var backend = new ReadBarrierCache(32);

        Assert.Throws<NotSupportedException>(() => new DistributedJtiCache(backend));
        Assert.Equal(0, backend.Reads);
    }

    // Every reader observes the absent marker before any writer runs. This is a valid
    // interleaving for a thread-safe distributed cache, including across independent nodes.
    private sealed class ReadBarrierCache(int readers) : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, byte[]> _entries = new();
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _reads;
        public int Reads => _reads;

        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            _entries.TryGetValue(key, out var snapshot);
            if (Interlocked.Increment(ref _reads) == readers)
            {
                _gate.TrySetResult();
            }

            await _gate.Task.WaitAsync(token);
            return snapshot;
        }

        public byte[]? Get(string key) => _entries.TryGetValue(key, out var value) ? value : null;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _entries[key] = value;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            Set(key, value, options);
            return Task.CompletedTask;
        }
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) => _entries.TryRemove(key, out _);
        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }
    }
}
