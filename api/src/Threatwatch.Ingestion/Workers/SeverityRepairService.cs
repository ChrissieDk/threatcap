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
/// V3 rows are rescored from their vector. V4 rows were first cleared (v4 could not be scored locally)
/// and the OSV watermark reset; a second pass (v2) scores them from their vector now that v4 is supported.
/// </summary>
public sealed class SeverityRepairService(
    IServiceScopeFactory scopeFactory,
    ILogger<SeverityRepairService> logger) : IHostedService
{
    public const string SettingKey = "repair.severity.v1";
    public const string SettingKeyV4 = "repair.severity.v2";
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
        await RunPassAsync(SettingKey, rescoreV3: true, ct);
        await RunPassAsync(SettingKeyV4, rescoreV3: false, ct);
    }

    private async Task RunPassAsync(string settingKey, bool rescoreV3, CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        if (await db.AppSettings.AnyAsync(s => s.Key == settingKey, ct)) return;

        var fixedV3 = 0;
        var clearedV4 = 0;
        var scoredV4 = 0;
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
                if (rescoreV3 && v.CvssSource == "CVSS_V3" && CvssCalculator.ScoreV3(v.CvssVector) is { } score)
                {
                    v.CvssScore = score;
                    v.Severity = Band(score);
                    fixedV3++;
                }
                else if (v.CvssSource == "CVSS_V4")
                {
                    var v4 = CvssV4Calculator.ScoreV4(v.CvssVector);
                    v.CvssScore = v4;
                    v.Severity = v4 is { } s4 ? Band(s4) : Severity.Unknown;
                    if (v4 is null) clearedV4++;
                    else scoredV4++;
                }

                v.PriorityScore = PriorityScoring.Compute(v.CvssScore, v.Severity, v.EpssScore, v.IsKnownExploited);
            }

            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        // Force the next OSV sync to re-read the retention window so unscorable V4 advisories regain their labels.
        if (clearedV4 > 0)
        {
            var osv = await db.IngestionStates.FirstOrDefaultAsync(s => s.Source == IngestionSource.Osv, ct);
            if (osv is not null) osv.Watermark = null;
        }

        db.AppSettings.Add(new AppSetting { Key = settingKey, ProtectedValue = "done", UpdatedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync(ct);
        logger.LogInformation(
            "Severity repair {Key} complete: {V3} v3 rescored, {Scored} v4 scored from vectors, {Cleared} v4 cleared for re-ingest.",
            settingKey, fixedV3, scoredV4, clearedV4);
    }

    private static Severity Band(decimal score) =>
        score switch { >= 9.0m => Severity.Critical, >= 7.0m => Severity.High, >= 4.0m => Severity.Medium, > 0m => Severity.Low, _ => Severity.Unknown };
}
