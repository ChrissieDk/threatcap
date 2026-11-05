using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Threatwatch.Ingestion.Workers;

/// <summary>
/// Interval loop for due providers. With <see cref="IngestionOptions.AutoStart"/> it
/// begins on boot; otherwise it stays idle until a signed-in user triggers a sync
/// (login, register, or Refresh), so the login page never starts a feed pull.
/// </summary>
public class IngestionWorker(
    IngestionRunner runner,
    IOptions<IngestionOptions> options,
    ILogger<IngestionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var opts = options.Value;
        var poll = TimeSpan.FromSeconds(Math.Max(5, opts.PollSeconds));

        try
        {
            if (opts.AutoStart)
            {
                logger.LogInformation("Ingestion worker auto-starting.");
                runner.RequestSync();
            }
            else
            {
                logger.LogInformation("Ingestion worker idle until sign-in.");
                await runner.WaitUntilEnabledAsync(stoppingToken);
                logger.LogInformation("Ingestion worker enabled after sign-in.");
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await runner.RunDueAsync(stoppingToken);
                await Task.Delay(poll, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
