using System.Diagnostics;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Ingestion.Workers;

public sealed record IngestionSyncStatusDto(
    bool Running,
    string? CurrentSource = null,
    DateTimeOffset? StartedAt = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    bool? Started = null);

/// <summary>
/// Single-flight coordinator for provider syncs. Nothing runs until
/// <see cref="RequestSync"/> (sign-in or Refresh). The hosted worker then keeps
/// due providers on their intervals so two OSV runs never overlap.
/// </summary>
public sealed class IngestionRunner(
    IServiceScopeFactory scopeFactory,
    IEnumerable<ISecurityDataSource> providers,
    ILogger<IngestionRunner> logger,
    IHostApplicationLifetime? lifetime = null)
{
    private static readonly TimeSpan JitterMax = TimeSpan.FromSeconds(5);

    private readonly List<ISecurityDataSource> _providers = providers.ToList();
    private readonly Dictionary<IngestionSource, DateTimeOffset> _lastRun = [];
    private readonly object _gate = new();
    private readonly TaskCompletionSource _enabled = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _forceRequested;
    private int _running;
    private string? _currentSource;
    private DateTimeOffset? _startedAt;
    private Task? _current;

    public bool IsRunning => Volatile.Read(ref _running) != 0;

    public bool IsEnabled => _enabled.Task.IsCompleted;

    public IngestionSyncStatusDto Status() => Snapshot(started: null);

    public Task WaitUntilEnabledAsync(CancellationToken ct) => _enabled.Task.WaitAsync(ct);

    public IngestionSyncStatusDto RequestSync()
    {
        _enabled.TrySetResult();

        bool started;
        lock (_gate)
        {
            if (_current is { IsCompleted: false })
            {
                started = false;
            }
            else
            {
                Interlocked.Exchange(ref _forceRequested, 1);
                StartLoop(lifetime?.ApplicationStopping ?? CancellationToken.None);
                started = true;
            }
        }

        return Snapshot(started);
    }

    public Task RunDueAsync(CancellationToken ct)
    {
        if (!_enabled.Task.IsCompleted)
        {
            return Task.CompletedTask;
        }

        EnsureLoop(ct);
        lock (_gate)
        {
            return _current ?? Task.CompletedTask;
        }
    }

    private bool EnsureLoop(CancellationToken ct)
    {
        lock (_gate)
        {
            if (_current is { IsCompleted: false })
            {
                return false;
            }

            StartLoop(ct);
            return true;
        }
    }

    private void StartLoop(CancellationToken ct)
    {
        Interlocked.Exchange(ref _running, 1);
        _startedAt = DateTimeOffset.UtcNow;
        _currentSource = null;
        _current = RunLoopAsync(ct);
    }

    private IngestionSyncStatusDto Snapshot(bool? started) =>
        new(
            IsRunning,
            IsRunning ? _currentSource : null,
            IsRunning ? _startedAt : null,
            started);

    private async Task RunLoopAsync(CancellationToken ct)
    {
        try
        {
            do
            {
                var force = Interlocked.Exchange(ref _forceRequested, 0) == 1;
                foreach (var provider in _providers)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!force
                        && _lastRun.TryGetValue(provider.Source, out var ranAt)
                        && DateTimeOffset.UtcNow - ranAt < provider.Interval)
                    {
                        continue;
                    }

                    await RunProviderAsync(provider, ct);
                    lock (_gate)
                    {
                        _lastRun[provider.Source] = DateTimeOffset.UtcNow;
                    }

                    if (!force)
                    {
                        var jitter = TimeSpan.FromMilliseconds(
                            Random.Shared.NextDouble() * JitterMax.TotalMilliseconds);
                        await Task.Delay(jitter, ct);
                    }
                }
            }
            while (Volatile.Read(ref _forceRequested) == 1);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown or test cancellation.
        }
        finally
        {
            _currentSource = null;
            _startedAt = null;
            Interlocked.Exchange(ref _running, 0);
        }
    }

    private async Task RunProviderAsync(ISecurityDataSource provider, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        _currentSource = provider.Name;
        logger.LogInformation("Ingestion '{Name}' started.", provider.Name);

        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();

            var state = await IngestionStateHelper.GetOrCreateAsync(db, provider.Source, ct);
            state.LastAttemptedSyncAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);

            var result = await provider.SyncAsync(scope, ct);
            sw.Stop();

            state.LastDurationMs = sw.ElapsedMilliseconds;

            if (result.Error is null)
            {
                state.LastSuccessfulSyncAt = DateTimeOffset.UtcNow;
                state.LastError = null;
                if (!string.IsNullOrEmpty(result.NewWatermark))
                {
                    state.Watermark = result.NewWatermark;
                }

                logger.LogInformation(
                    "Ingestion '{Name}' succeeded in {Ms}ms: {Count} records.",
                    provider.Name, sw.ElapsedMilliseconds, result.RecordsProcessed);
            }
            else
            {
                state.LastError = result.Error;
                logger.LogWarning("Ingestion '{Name}' reported error: {Error}", provider.Name, result.Error);
            }

            await db.SaveChangesAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown; nothing to record.
        }
        catch (Exception ex)
        {
            sw.Stop();
            logger.LogError(ex, "Ingestion '{Name}' failed.", provider.Name);

            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
                var state = await IngestionStateHelper.GetOrCreateAsync(db, provider.Source, ct);
                state.LastAttemptedSyncAt = DateTimeOffset.UtcNow;
                state.LastError = ex.Message;
                state.LastDurationMs = sw.ElapsedMilliseconds;
                await db.SaveChangesAsync(ct);
            }
            catch (Exception inner)
            {
                logger.LogError(inner, "Failed to record ingestion failure state for '{Name}'.", provider.Name);
            }
        }
    }
}
