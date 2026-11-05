using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Alerts;

namespace Threatwatch.Ingestion.Alerts;

/// <summary>Periodically enqueues newly matching items and delivers pending alerts.</summary>
public class AlertWorker(
    IServiceScopeFactory scopeFactory,
    IOptions<AlertOptions> options,
    ILogger<AlertWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var poll = TimeSpan.FromSeconds(Math.Max(15, options.Value.PollSeconds));
        try
        {
            // Give startup (migrations, seeding, first ingestion) a head start.
            await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await using var scope = scopeFactory.CreateAsyncScope();
                    var queued = await scope.ServiceProvider.GetRequiredService<AlertService>().EnqueueAsync(stoppingToken);
                    var sent = await scope.ServiceProvider.GetRequiredService<AlertDispatcher>().DeliverPendingAsync(stoppingToken);
                    if (queued > 0 || sent > 0)
                    {
                        logger.LogInformation("Alerts: {Queued} queued, {Sent} messages sent.", queued, sent);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Alert cycle failed.");
                }

                await Task.Delay(poll, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }
}
