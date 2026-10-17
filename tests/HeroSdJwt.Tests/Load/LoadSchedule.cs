namespace HeroSdJwt.Tests.Load;

internal sealed record LoadStage(int Rate, TimeSpan Interval, TimeSpan Duration, bool Ramp = false);
internal readonly record struct LoadBatch(TimeSpan Offset, int Count);

/// <summary>Finite, open-model arrivals. Ramps continue from the preceding stage's target rate.</summary>
internal sealed class LoadSchedule
{
    internal const int MAX_REQUESTS = 1_000_000;
    private const int MAX_BATCHES = 60_000;

    internal LoadSchedule(params LoadStage[] stages)
    {
        ArgumentNullException.ThrowIfNull(stages);
        if (stages.Length == 0)
        {
            throw new ArgumentException("At least one load stage is required.", nameof(stages));
        }

        var batches = new List<LoadBatch>();
        int previousRate = 0;
        long durationTicks = 0;
        long requests = 0;
        foreach (var stage in stages)
        {
            ArgumentNullException.ThrowIfNull(stage);
            if (stage.Rate <= 0 || stage.Rate > MAX_REQUESTS || stage.Interval <= TimeSpan.Zero ||
                stage.Duration <= TimeSpan.Zero || stage.Duration > TimeSpan.FromHours(1))
            {
                throw new ArgumentOutOfRangeException(nameof(stages), "Rates and intervals must be positive; each stage is limited to one hour.");
            }
            if (stage.Duration.Ticks % stage.Interval.Ticks != 0)
            {
                throw new ArgumentException("Stage duration must be a whole number of intervals.", nameof(stages));
            }
            long intervals = stage.Duration.Ticks / stage.Interval.Ticks;
            if (intervals > MAX_BATCHES - batches.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(stages), "Too many load intervals.");
            }

            for (int i = 0; i < intervals; i++)
            {
                int count = stage.Ramp
                    ? (int)Math.Round(previousRate + (stage.Rate - previousRate) * (i / (double)intervals), MidpointRounding.AwayFromZero)
                    : stage.Rate;
                requests += count;
                if (requests > MAX_REQUESTS)
                {
                    throw new ArgumentOutOfRangeException(nameof(stages), "Too many scheduled requests.");
                }
                batches.Add(new LoadBatch(TimeSpan.FromTicks(durationTicks + i * stage.Interval.Ticks), count));
            }
            durationTicks = checked(durationTicks + stage.Duration.Ticks);
            previousRate = stage.Rate;
        }

        Batches = batches.AsReadOnly();
        Duration = TimeSpan.FromTicks(durationTicks);
        RequestCount = (int)requests;
    }

    internal IReadOnlyList<LoadBatch> Batches { get; }
    internal TimeSpan Duration { get; }
    internal int RequestCount { get; }

    // Deterministic spacing avoids bursts and random timing in correctness tests. No warm-up is added.
    internal IEnumerable<TimeSpan> Arrivals()
    {
        for (int i = 0; i < Batches.Count; i++)
        {
            var batch = Batches[i];
            var end = i + 1 < Batches.Count ? Batches[i + 1].Offset : Duration;
            for (int j = 0; j < batch.Count; j++)
            {
                yield return batch.Offset + TimeSpan.FromTicks((long)((end - batch.Offset).Ticks * ((j + 0.5) / batch.Count)));
            }
        }
    }
}
