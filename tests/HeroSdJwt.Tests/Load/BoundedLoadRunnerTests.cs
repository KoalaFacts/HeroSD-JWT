namespace HeroSdJwt.Tests.Load;

public class BoundedLoadRunnerTests
{
    private static LoadSchedule ShortSchedule(int count = 4) => new(new LoadStage(count, TimeSpan.FromMilliseconds(40), TimeSpan.FromMilliseconds(40)));

    [Fact]
    public async Task Should_ExecuteEveryArrivalAndWaitForFullDuration()
    {
        int calls = 0;
        var scenario = new LoadScenario("success", ShortSchedule(), (_, _) =>
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(true);
        });
        var result = Assert.Single(await BoundedLoadRunner.RunAsync([scenario], TestContext.Current.CancellationToken));
        Assert.Equal(4, calls);
        Assert.Equal(4, result.SuccessCount);
        Assert.Equal(0, result.FailureCount);
        Assert.True(result.Duration >= scenario.Schedule.Duration);
        Assert.True(result.RequestsPerSecond <= 100);
    }

    [Fact]
    public async Task Should_CountFalseResultsAndExceptionsWithoutLosingLaterArrivals()
    {
        var scenario = new LoadScenario("failures", ShortSchedule(), (id, _) => id == 1
            ? throw new InvalidOperationException("expected failure")
            : ValueTask.FromResult(id != 2));
        var result = Assert.Single(await BoundedLoadRunner.RunAsync([scenario], TestContext.Current.CancellationToken));
        Assert.Equal(2, result.SuccessCount);
        Assert.Equal(2, result.FailureCount);
        Assert.Contains(result.Errors, error => error.Contains("expected failure", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Should_RunScenariosConcurrently()
    {
        var otherStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = new LoadScenario("first", ShortSchedule(1), async (_, token) =>
        {
            await otherStarted.Task.WaitAsync(token);
            return true;
        });
        var second = new LoadScenario("second", ShortSchedule(1), (_, _) =>
        {
            otherStarted.SetResult();
            return ValueTask.FromResult(true);
        });
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        var results = await BoundedLoadRunner.RunAsync([first, second], timeout.Token);
        Assert.Equal(2, results.Length);
        Assert.All(results, result => Assert.Equal(1, result.SuccessCount));
    }

    [Fact]
    public async Task Should_BoundConcurrencyAndCountEveryRejectedArrival()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int running = 0;
        int maximum = 0;
        var scenario = new LoadScenario("overload", ShortSchedule(100), async (_, token) =>
        {
            maximum = Math.Max(maximum, Interlocked.Increment(ref running));
            started.TrySetResult();
            try
            {
                await release.Task.WaitAsync(token);
                return true;
            }
            finally
            {
                Interlocked.Decrement(ref running);
            }
        });
        var run = BoundedLoadRunner.RunAsync([scenario], TestContext.Current.CancellationToken, concurrency: 1, queueCapacity: 1);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        release.SetResult();
        var result = Assert.Single(await run);
        Assert.Equal(1, maximum);
        Assert.Equal(0, running);
        Assert.True(result.RejectedCount > 0);
        Assert.Equal(100, result.SuccessCount + result.FailureCount);
        Assert.Equal(result.RejectedCount, result.FailureCount);
        Assert.True(result.Duration >= TimeSpan.FromMilliseconds(100));
    }

    [Fact]
    public async Task Should_DrainAndCancelWorkersBeforeReturningCancellation()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int running = 0;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var scenario = new LoadScenario("cancel", ShortSchedule(), async (_, token) =>
        {
            Interlocked.Increment(ref running);
            started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return true;
            }
            finally
            {
                Interlocked.Decrement(ref running);
            }
        });
        var run = BoundedLoadRunner.RunAsync([scenario], cancellation.Token, concurrency: 2);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(0, running);
    }

    [Fact]
    public async Task Should_ValidateBoundsBeforeStartingOperations()
    {
        var scenario = new LoadScenario("unused", ShortSchedule(), (_, _) => throw new InvalidOperationException("must not run"));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => BoundedLoadRunner.RunAsync([scenario], TestContext.Current.CancellationToken, concurrency: 0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => BoundedLoadRunner.RunAsync([scenario], TestContext.Current.CancellationToken, queueCapacity: 0));
        await Assert.ThrowsAsync<ArgumentException>(() => BoundedLoadRunner.RunAsync([scenario, scenario], TestContext.Current.CancellationToken));
    }
}
