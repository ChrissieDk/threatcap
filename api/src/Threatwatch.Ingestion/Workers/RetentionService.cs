using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;

namespace Threatwatch.Ingestion.Workers;

public class RetentionOptions
{
    /// <summary>When true (default) nothing is deleted; the run only logs what it would remove.</summary>
    public bool DryRun { get; set; } = true;

    public bool Enabled { get; set; } = true;

    /// <summary>Advisories not modified for this long are removed. Keep it above Osv:RetentionDays.</summary>
    public int AdvisoryDays { get; set; } = 180;

    /// <summary>Withdrawn advisories are removed this long after their last modification.</summary>
    public int WithdrawnDays { get; set; } = 30;

    /// <summary>Update and fix-available events older than this are removed; first-seen and known-exploited events are kept.</summary>
    public int EventDays { get; set; } = 90;

    /// <summary>Resolved incidents are removed this long after resolution.</summary>
    public int ResolvedIncidentDays { get; set; } = 180;

    public int IntervalHours { get; set; } = 24;
}

public sealed record RetentionResult(int Advisories, int Withdrawn, int Events, int Incidents);

/// <summary>
/// Keeps the database bounded. Ingestion only limits what each sync reads, so without this stored
/// advisories, events and resolved incidents would grow forever. Known-exploited advisories and
/// advisories affecting a package in a user's project are never removed for being stale.
/// </summary>
public sealed class RetentionService(
    IServiceScopeFactory scopeFactory,
    IOptions<RetentionOptions> options,
    ILogger<RetentionService> logger) : BackgroundService
{
    private const int BatchSize = 200;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;

        try
        {
            // Let startup repair and the first sync get going before pruning.
            await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await RunOnceAsync(DateTimeOffset.UtcNow, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "Retention run failed; it will retry next interval.");
                }

                await Task.Delay(TimeSpan.FromHours(Math.Max(1, options.Value.IntervalHours)), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public async Task<RetentionResult> RunOnceAsync(DateTimeOffset now, CancellationToken ct)
    {
        var opts = options.Value;
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();

        var staleCutoff = now.AddDays(-Math.Max(1, opts.AdvisoryDays));
        var withdrawnCutoff = now.AddDays(-Math.Max(1, opts.WithdrawnDays));

        var projectPackages = (await db.ProjectDependencies
                .Select(d => new { d.Ecosystem, d.Name })
                .Distinct()
                .ToListAsync(ct))
            .Select(d => (d.Ecosystem, d.Name))
            .ToHashSet();

        int stale = 0, withdrawn = 0;
        Guid? last = null;
        while (true)
        {
            var batch = await db.Vulnerabilities
                .Where(v => last == null || v.Id.CompareTo(last.Value) > 0)
                .Where(v => (v.IsWithdrawn && v.ModifiedAt < withdrawnCutoff)
                            || (!v.IsKnownExploited && v.ModifiedAt < staleCutoff))
                .OrderBy(v => v.Id)
                .Take(BatchSize)
                .Include(v => v.AffectedPackages)
                .ToListAsync(ct);
            if (batch.Count == 0) break;
            last = batch[^1].Id;

            // Withdrawn advisories go regardless; stale ones are kept while a project depends on them.
            var doomed = batch
                .Where(v => v.IsWithdrawn && v.ModifiedAt < withdrawnCutoff
                            || !v.AffectedPackages.Any(p => projectPackages.Contains((p.Ecosystem, p.PackageName))))
                .ToList();
            withdrawn += doomed.Count(v => v.IsWithdrawn);
            stale += doomed.Count(v => !v.IsWithdrawn);
            if (opts.DryRun || doomed.Count == 0)
            {
                db.ChangeTracker.Clear();
                continue;
            }

            var ids = doomed.Select(v => v.Id).ToList();
            db.ChangeTracker.Clear();
            var full = await db.Vulnerabilities
                .Where(v => ids.Contains(v.Id))
                .Include(v => v.AffectedPackages).Include(v => v.Aliases)
                .Include(v => v.SourceReferences).Include(v => v.Events)
                .ToListAsync(ct);
            db.Vulnerabilities.RemoveRange(full);
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        var eventCutoff = now.AddDays(-Math.Max(1, opts.EventDays));
        var oldEvents = db.VulnerabilityEvents.Where(e => e.EventAt < eventCutoff
            && (e.EventType == VulnerabilityEventType.AdvisoryUpdated
                || e.EventType == VulnerabilityEventType.FixAvailable
                || e.EventType == VulnerabilityEventType.SeverityChanged));
        var events = await oldEvents.CountAsync(ct);

        var incidentCutoff = now.AddDays(-Math.Max(1, opts.ResolvedIncidentDays));
        var oldIncidents = db.SecurityIncidents.Where(i => i.Status == IncidentStatus.Resolved
            && i.ResolvedAt != null && i.ResolvedAt < incidentCutoff);
        var incidents = await oldIncidents.CountAsync(ct);

        if (!opts.DryRun)
        {
            db.VulnerabilityEvents.RemoveRange(await oldEvents.ToListAsync(ct));
            db.SecurityIncidents.RemoveRange(await oldIncidents.ToListAsync(ct));
            await db.SaveChangesAsync(ct);
        }

        var result = new RetentionResult(stale, withdrawn, events, incidents);
        logger.LogInformation(
            "Retention {Mode}: {Advisories} stale and {Withdrawn} withdrawn advisories, {Events} events, {Incidents} resolved incidents.",
            opts.DryRun ? "dry run (nothing deleted)" : "removed", result.Advisories, result.Withdrawn, result.Events, result.Incidents);
        return result;
    }
}
