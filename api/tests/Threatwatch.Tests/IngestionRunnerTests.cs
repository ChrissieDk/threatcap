using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Workers;

namespace Threatwatch.Tests;

public class IngestionRunnerTests : IDisposable
{
    private readonly ServiceProvider _services;
    private readonly FakeSource _source;
    private readonly IngestionRunner _runner;

    public IngestionRunnerTests()
    {
        var services = new ServiceCollection();
        services.AddDbContext<ThreatwatchDbContext>(options =>
            options.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        _services = services.BuildServiceProvider();
        _source = new FakeSource();
        _runner = new IngestionRunner(
            _services.GetRequiredService<IServiceScopeFactory>(),
            [_source],
            NullLogger<IngestionRunner>.Instance);
    }

    public void Dispose() => _services.Dispose();

    [Fact]
    public async Task RunDueDoesNothingUntilAUserRequestsSync()
    {
        Assert.False(_runner.IsEnabled);
        _source.Hold = false;
        await _runner.RunDueAsync(CancellationToken.None);
        Assert.Equal(0, _source.Runs);
        Assert.False(_runner.IsRunning);
    }

    [Fact]
    public async Task RequestSyncRunsTheProviderImmediately()
    {
        var status = _runner.RequestSync();
        Assert.True(status.Started);
        Assert.True(status.Running);
        Assert.True(_runner.IsRunning);

        await WaitUntil(() => _source.Runs == 1);
        _source.Release();
        await _runner.RunDueAsync(CancellationToken.None);
        Assert.Equal(1, _source.Runs);
        Assert.False(_runner.IsRunning);
    }

    [Fact]
    public async Task RequestSyncDuringARunDoesNotOverlapTheProvider()
    {
        _runner.RequestSync();
        await WaitUntil(() => _source.Runs == 1);

        var second = _runner.RequestSync();
        Assert.False(second.Started);
        Assert.True(second.Running);
        Assert.Equal(1, _source.Runs);

        _source.Hold = false;
        _source.Release();
        await _runner.RunDueAsync(CancellationToken.None);
        Assert.Equal(1, _source.Runs);
    }

    [Fact]
    public async Task RunDueRespectsProviderIntervalUntilForced()
    {
        _source.Hold = false;
        _runner.RequestSync();
        await _runner.RunDueAsync(CancellationToken.None);
        Assert.Equal(1, _source.Runs);

        await _runner.RunDueAsync(CancellationToken.None);
        Assert.Equal(1, _source.Runs);

        _runner.RequestSync();
        await WaitUntil(() => _source.Runs == 2);
        await _runner.RunDueAsync(CancellationToken.None);
        Assert.Equal(2, _source.Runs);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("Condition was not met in time.");
            }

            await Task.Delay(20);
        }
    }

    private sealed class FakeSource : ISecurityDataSource
    {
        private TaskCompletionSource _gate = NewGate();

        public string Name => "fake";
        public IngestionSource Source => IngestionSource.Osv;
        public TimeSpan Interval => TimeSpan.FromHours(1);
        public int Runs;
        public bool Hold = true;

        public async Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct)
        {
            Interlocked.Increment(ref Runs);
            if (Hold)
            {
                await _gate.Task.WaitAsync(ct);
            }

            return IngestionResult.Success(1, null);
        }

        public void Release()
        {
            _gate.TrySetResult();
            _gate = NewGate();
        }

        private static TaskCompletionSource NewGate() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
