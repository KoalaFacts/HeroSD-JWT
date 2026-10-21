namespace HeroSdJwt.Tests.Load;

public class LoadRunnerTests
{
    [Fact]
    public void Should_KeepInjectBatchesAndDuration()
    {
        var schedule = new LoadSchedule(new LoadStage(100, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10)));
        Assert.Equal(1000, schedule.RequestCount);
        Assert.Equal(TimeSpan.FromSeconds(10), schedule.Duration);
        Assert.Equal(Enumerable.Range(0, 10).Select(i => new LoadBatch(TimeSpan.FromSeconds(i), 100)), schedule.Batches);
    }

    [Fact]
    public void Should_RejectUnboundedOrInvalidSchedules()
    {
        Assert.Throws<ArgumentException>(() => new LoadSchedule());
        Assert.Throws<ArgumentOutOfRangeException>(() => new LoadSchedule(new LoadStage(-1, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1))));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LoadSchedule(new LoadStage(1, TimeSpan.Zero, TimeSpan.FromSeconds(1))));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LoadSchedule(new LoadStage(1, TimeSpan.FromSeconds(1), TimeSpan.Zero)));
        Assert.Throws<ArgumentException>(() => new LoadSchedule(new LoadStage(1, TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1500))));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LoadSchedule(new LoadStage(1_000_001, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1))));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LoadSchedule(new LoadStage(1, TimeSpan.FromTicks(1), TimeSpan.FromSeconds(1))));
    }

    [Fact]
    public void Should_CountFailuresAndUseSuccessfulNearestRankP99()
    {
        var statistics = new LoadStatistics(105);
        for (int i = 100; i > 0; i--)
        {
            statistics.Record(true, TimeSpan.FromMilliseconds(i));
        }
        statistics.Record(false, TimeSpan.FromSeconds(20), "Invalid signature");
        statistics.Reject(4);

        var result = statistics.Complete("sample", TimeSpan.FromSeconds(10));
        Assert.Equal(100, result.SuccessCount);
        Assert.Equal(5, result.FailureCount);
        Assert.Equal(4, result.RejectedCount);
        Assert.Equal(10, result.RequestsPerSecond);
        Assert.Equal(99, result.P99Milliseconds);
        Assert.Equal(5d / 105, result.FailureRate);
        Assert.Contains("Invalid signature", result.Errors);
    }

    [Fact]
    public void Should_NotReportEmptyRunAsPassingLatencyOrFailureRate()
    {
        var result = new LoadStatistics(1).Complete("empty", TimeSpan.FromSeconds(1));
        Assert.Equal(double.PositiveInfinity, result.P99Milliseconds);
        Assert.Equal(1, result.FailureRate);
        Assert.Equal(0, result.RequestsPerSecond);
    }

    [Fact]
    public void Should_BoundSamplesAndErrorDetails()
    {
        var statistics = new LoadStatistics(10);
        for (int i = 0; i < 10; i++)
        {
            statistics.Record(false, TimeSpan.Zero, new string('x', 1000));
        }
        var result = statistics.Complete("errors", TimeSpan.FromSeconds(1));
        Assert.Equal(10, result.FailureCount);
        Assert.Equal(5, result.Errors.Count);
        Assert.All(result.Errors, error => Assert.True(error.Length <= 512));
        Assert.Throws<InvalidOperationException>(() => statistics.Record(true, TimeSpan.Zero));
    }
    [Fact]
    public void Should_RampFromZeroAndInheritEachPreviousTarget()
    {
        var schedule = new LoadSchedule([.. new[] { 10, 50, 100, 200 }
            .Select(rate => new LoadStage(rate, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10), Ramp: true))]);
        int[] counts = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, 14, 18, 22, 26, 30, 34, 38, 42, 46,
            50, 55, 60, 65, 70, 75, 80, 85, 90, 95,
            100, 110, 120, 130, 140, 150, 160, 170, 180, 190];
        Assert.Equal(counts, schedule.Batches.Select(batch => batch.Count));
        Assert.Equal(2500, schedule.RequestCount);
        Assert.Equal(TimeSpan.FromSeconds(40), schedule.Duration);
    }

    [Fact]
    public void Should_SpaceArrivalsWithinEachIntervalWithoutExtraEndpoint()
    {
        var schedule = new LoadSchedule(new LoadStage(2, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)));
        Assert.Equal(new[] { 0.25, 0.75, 1.25, 1.75 }.Select(TimeSpan.FromSeconds), schedule.Arrivals());
    }

}
