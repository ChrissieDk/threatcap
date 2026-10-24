using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Threatwatch.Ingestion.Workers;

/// <summary>
/// Interval loop for due providers. It stays idle until a signed-in user triggers
/// a sync (login, register, or Refresh), so the login page never starts a feed pull.
/// </summary>
public class IngestionWorker(
    IngestionRunner runner,
    ILogger<IngestionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Ingestion worker idle until sign-in.");
        try
        {
            await runner.WaitUntilEnabledAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        logger.LogInformation("Ingestion worker enabled after sign-in.");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await runner.RunDueAsync(stoppingToken);
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
