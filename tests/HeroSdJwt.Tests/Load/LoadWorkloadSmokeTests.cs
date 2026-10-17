namespace HeroSdJwt.Tests.Load;

/// <summary>Small functional proof only; these checks do not run or certify the manual load baselines.</summary>
public class LoadWorkloadSmokeTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Should_ExecuteAllFiveRealWorkloadsWithTheReplacementRunner()
    {
        var schedule = new LoadSchedule(new LoadStage(4, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100)));
        var token = TestContext.Current.CancellationToken;
        LoadResult[] singleResults =
        [
            await SdJwtLoadTests.RunIssuanceAsync(schedule, token),
            await SdJwtLoadTests.RunVerificationAsync(schedule, token),
            await SdJwtLoadTests.RunKeyBindingAsync(schedule, token),
            await SdJwtLoadTests.RunStressAsync(schedule, token)
        ];
        Assert.All(singleResults, result =>
        {
            output.WriteLine(result.ToString());
            Assert.Equal(4, result.SuccessCount);
            Assert.Equal(0, result.FailureCount);
            Assert.Equal(0, result.RejectedCount);
            Assert.True(double.IsFinite(result.P99Milliseconds));
        });

        var verificationSchedule = new LoadSchedule(new LoadStage(8, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100)));
        var mixed = await SdJwtLoadTests.RunMixedAsync(schedule, verificationSchedule, token);
        var issuance = mixed.Single(result => result.Name == "issuance");
        var verification = mixed.Single(result => result.Name == "verification");
        foreach (var result in mixed)
        {
            output.WriteLine(result.ToString());
            Assert.Equal(0, result.RejectedCount);
        }
        Assert.Equal(4, issuance.SuccessCount);
        Assert.Equal(0, issuance.FailureCount);
        Assert.InRange(verification.SuccessCount, 0, 4);
        Assert.Equal(8, verification.SuccessCount + verification.FailureCount);
        Assert.True(verification.FailureCount >= 4); // Empty reads stay failed; no prefilling or reuse.
    }

    [Fact]
    public async Task Should_FailEmptyMixedReadsAndConsumeEachIssuedPresentationOnce()
    {
        var schedule = new LoadSchedule(new LoadStage(1, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1)));
        var scenarios = SdJwtLoadTests.CreateMixedScenarios(schedule, schedule);
        var issue = scenarios.Single(scenario => scenario.Name == "issuance").Operation;
        var verify = scenarios.Single(scenario => scenario.Name == "verification").Operation;
        var token = TestContext.Current.CancellationToken;

        Assert.False(await verify(1, token));
        Assert.True(await issue(1, token));
        Assert.True(await verify(2, token));
        Assert.False(await verify(3, token));
    }
}
