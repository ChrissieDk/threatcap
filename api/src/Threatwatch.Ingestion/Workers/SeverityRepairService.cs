using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Scoring;

namespace Threatwatch.Ingestion.Workers;

/// <summary>
/// One-time repair for advisories stored before CVSS scores were calculated correctly: the old
/// parser stored the CVSS version number (3.1 / 4.0) as the score, so nothing was ever High or
/// Critical. Runs at startup, before ingestion starts, and records completion so it only runs once.
/// V3 rows are rescored from their vector; V4 rows cannot be scored locally, so their bogus value is
/// cleared and the OSV watermark is reset so the next sync re-reads their labels from the source.
/// </summary>
public sealed class SeverityRepairService(
    IServiceScopeFactory scopeFactory,
    ILogger<SeverityRepairService> logger) : IHostedService
{
    public const string SettingKey = "repair.severity.v1";
    private const int BatchSize = 1000;

    public async Task StartAsync(CancellationToken ct)
    {
        try
        {
            await RunAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never block startup (e.g. the migration that creates AppSettings has not been applied yet).
            logger.LogWarning(ex, "Severity repair skipped; it will retry on the next start.");
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;

    public async Task RunAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        if (await db.AppSettings.AnyAsync(s => s.Key == SettingKey, ct)) return;

        var fixedV3 = 0;
        var clearedV4 = 0;
        Guid? last = null;
        while (true)
        {
            var batch = await db.Vulnerabilities
                .Where(v => last == null || v.Id.CompareTo(last.Value) > 0)
                .OrderBy(v => v.Id)
                .Take(BatchSize)
                .ToListAsync(ct);
            if (batch.Count == 0) break;
            last = batch[^1].Id;

            foreach (var v in batch)
            {
                if (v.CvssSource == "CVSS_V3" && CvssCalculator.ScoreV3(v.CvssVector) is { } score)
                {
                    v.CvssScore = score;
                    v.Severity = score switch { >= 9.0m => Severity.Critical, >= 7.0m => Severity.High, >= 4.0m => Severity.Medium, > 0m => Severity.Low, _ => Severity.Unknown };
                    fixedV3++;
                }
                else if (v.CvssSource == "CVSS_V4")
                {
                    v.CvssScore = null;
                    v.Severity = Severity.Unknown;
                    clearedV4++;
                }

                v.PriorityScore = PriorityScoring.Compute(v.CvssScore, v.Severity, v.EpssScore, v.IsKnownExploited);
            }

            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        // Force the next OSV sync to re-read the retention window so V4-only advisories regain their labels.
        var osv = await db.IngestionStates.FirstOrDefaultAsync(s => s.Source == IngestionSource.Osv, ct);
        if (osv is not null) osv.Watermark = null;

        db.AppSettings.Add(new AppSetting { Key = SettingKey, ProtectedValue = "done", UpdatedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Severity repair complete: {V3} rescored from vectors, {V4} v4 scores cleared for re-ingest.", fixedV3, clearedV4);
    }
}
