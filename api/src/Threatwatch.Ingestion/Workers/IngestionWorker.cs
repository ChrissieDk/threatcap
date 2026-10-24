using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Ingestion.Workers;

/// <summary>
/// Background loop that runs every registered <see cref="ISecurityDataSource"/> on
/// its own interval. Each provider is isolated in a try/catch so one failing source
/// never blocks others; <see cref="Core.Entities.IngestionState"/> is updated with
/// attempt/success/duration/error and the provider's watermark on success.
/// </summary>
public class IngestionWorker(
    IServiceScopeFactory scopeFactory,
    IEnumerable<ISecurityDataSource> providers,
    ILogger<IngestionWorker> logger) : BackgroundService
{
    private static readonly TimeSpan JitterMax = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var providerList = providers.ToList();
        var lastRun = new Dictionary<IngestionSource, DateTimeOffset>();

        while (!stoppingToken.IsCancellationRequested)
        {
            foreach (var provider in providerList)
            {
                if (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                if (lastRun.TryGetValue(provider.Source, out var ranAt)
                    && DateTimeOffset.UtcNow - ranAt < provider.Interval)
                {
                    continue;
                }

                await RunProviderAsync(provider, stoppingToken);

                lastRun[provider.Source] = DateTimeOffset.UtcNow;

                // Jitter between providers to avoid hammering external APIs in lockstep.
                var jitter = TimeSpan.FromMilliseconds(Random.Shared.NextDouble() * JitterMax.TotalMilliseconds);
                await Task.Delay(jitter, stoppingToken);
            }

            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    private async Task RunProviderAsync(ISecurityDataSource provider, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
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

            // Re-fetch: SyncAsync may have run in the same scope; state is tracked there.
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
