using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Data;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Ingestion.Workers;

/// <summary>
/// Optional backfill path: reads a local directory of extracted OSV JSON files
/// (one record per file, the same format as the gs://osv-vulnerabilities/&lt;ecosystem&gt;/all.zip
/// exports) and ingests them. Directory comes from env OSV_BACKFILL_DIR; the
/// service only runs when that variable is set.
/// </summary>
public class OsvBackfillService(
    IServiceScopeFactory scopeFactory,
    ILogger<OsvBackfillService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var dir = Environment.GetEnvironmentVariable("OSV_BACKFILL_DIR");
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            logger.LogInformation("OSV backfill disabled (OSV_BACKFILL_DIR not set or missing).");
            return;
        }

        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var upserter = scope.ServiceProvider.GetRequiredService<VulnerabilityUpserter>();

        var files = Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories).ToList();
        logger.LogInformation("OSV backfill starting with {Count} files from {Dir}.", files.Count, dir);

        var processed = 0;
        foreach (var file in files)
        {
            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                var json = await File.ReadAllTextAsync(file, stoppingToken);
                var record = Normalization.OsvJsonReader.Deserialize<OsvRecord>(json);
                if (record is not null)
                {
                    await upserter.UpsertOsvRecordAsync(record, stoppingToken);
                    processed++;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Backfill failed for {File}; continuing.", file);
            }
        }

        logger.LogInformation("OSV backfill completed: {Processed}/{Total} records.", processed, files.Count);
    }
}
