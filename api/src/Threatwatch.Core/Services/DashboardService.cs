using System.Globalization;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Services;

public record DailyPointDto(string Date, int Count);

public record LastSyncDto(string Source, DateTimeOffset? LastSuccessfulSyncAt, string? LastError);

public record DashboardSummaryDto(
    int NewVulnerabilities,
    int CriticalHigh,
    int KevAdded,
    int ActiveIncidents,
    int FollowedCount,
    int FollowedTopicsWithActivity,
    IReadOnlyList<LastSyncDto> LastSyncs);

public record ActNowItemDto(
    Guid Id,
    string CanonicalId,
    string Title,
    Severity Severity,
    double? PriorityScore,
    string? PrimaryVendor,
    string? PrimaryProduct,
    ProductType? ProductType,
    double? EpssScore,
    double? EpssPercentile,
    bool IsKnownExploited,
    DateTimeOffset PublishedAt);

public class DashboardService(ThreatwatchDbContext db, FollowService follows)
{
    public async Task<DashboardSummaryDto> GetSummaryAsync(int days, Guid userId, bool following, CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        var techs = following
            ? await follows.ListFollowedTechnologiesAsync(userId, ct)
            : [];

        IQueryable<Vulnerability> vulns = db.Vulnerabilities.Where(v => v.PublishedAt >= cutoff);
        if (following)
        {
            vulns = vulns.WhereMatchesAny(techs);
        }

        var newVulns = await vulns.CountAsync(ct);
        var criticalHigh = await vulns.CountAsync(
            v => v.Severity == Severity.Critical || v.Severity == Severity.High, ct);

        IQueryable<VulnerabilityEvent> kevEvents = db.VulnerabilityEvents
            .Where(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded && e.EventAt >= cutoff);
        if (following)
        {
            var matched = db.Vulnerabilities.WhereMatchesAny(techs);
            kevEvents = kevEvents.Where(e => matched.Any(v => v.Id == e.VulnerabilityId));
        }

        var kevAdded = await kevEvents.CountAsync(ct);
        var activeIncidents = await db.SecurityIncidents.CountAsync(
            i => i.Status != IncidentStatus.Resolved, ct);
        var lastSyncs = await db.IngestionStates
            .OrderBy(s => s.Source)
            .Select(s => new LastSyncDto(s.Source.ToString(), s.LastSuccessfulSyncAt, s.LastError))
            .ToListAsync(ct);

        var followList = await follows.ListAsync(userId, days, ct);

        return new DashboardSummaryDto(
            newVulns,
            criticalHigh,
            kevAdded,
            activeIncidents,
            followList.Count,
            followList.Count(item => item.RecentActivityCount > 0),
            lastSyncs);
    }

    public async Task<IReadOnlyList<ActNowItemDto>> GetActNowAsync(
        int top, int days, Guid userId, CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        var techs = await follows.ListFollowedTechnologiesAsync(userId, ct);
        if (techs.Count == 0)
        {
            return [];
        }

        return await db.Vulnerabilities
            .WhereMatchesAny(techs)
            .Where(v => v.PriorityScore != null
                && (v.PublishedAt >= cutoff
                    || v.Events.Any(e =>
                        e.EventType == VulnerabilityEventType.KnownExploitedAdded && e.EventAt >= cutoff)))
            .OrderByDescending(v => v.PriorityScore)
            .Take(top)
            .Select(v => new ActNowItemDto(
                v.Id,
                v.CanonicalId,
                v.Title,
                v.Severity,
                v.PriorityScore,
                v.PrimaryVendor,
                v.PrimaryProduct,
                v.ProductType,
                v.EpssScore,
                v.EpssPercentile,
                v.IsKnownExploited,
                v.PublishedAt))
            .ToListAsync(ct);
    }

    public async Task<IReadOnlyList<DailyPointDto>> GetDailyAsync(
        string metric,
        int days,
        Guid userId,
        bool following,
        CancellationToken ct)
    {
        var today = DateTime.UtcNow.Date;
        var start = new DateTimeOffset(today.AddDays(-(days - 1)), TimeSpan.Zero);
        var techs = following
            ? await follows.ListFollowedTechnologiesAsync(userId, ct)
            : new List<Technology>();

        var timestamps = metric switch
        {
            "disclosures" => await DisclosureTimesAsync(start, techs, following, ct),
            "updates" => await EventTimesAsync(
                start,
                techs,
                following,
                e => e.EventType == VulnerabilityEventType.AdvisoryUpdated
                    || e.EventType == VulnerabilityEventType.SeverityChanged,
                ct),
            "kev" => await EventTimesAsync(
                start,
                techs,
                following,
                e => e.EventType == VulnerabilityEventType.KnownExploitedAdded,
                ct),
            "incidents" => await db.SecurityIncidents
                .Where(i => i.StartedAt >= start)
                .Select(i => i.StartedAt)
                .ToListAsync(ct),
            _ => throw new ArgumentException($"Unknown metric '{metric}'.", nameof(metric)),
        };

        var byDate = timestamps
            .GroupBy(t => t.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))
            .ToDictionary(g => g.Key, g => g.Count());

        var result = new List<DailyPointDto>(days);
        for (var d = 0; d < days; d++)
        {
            var date = start.AddDays(d).UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            result.Add(new DailyPointDto(date, byDate.GetValueOrDefault(date)));
        }

        return result;
    }

    private async Task<List<DateTimeOffset>> DisclosureTimesAsync(
        DateTimeOffset start,
        IReadOnlyList<Technology> techs,
        bool following,
        CancellationToken ct)
    {
        IQueryable<Vulnerability> query = db.Vulnerabilities.Where(v => v.PublishedAt >= start);
        if (following)
        {
            query = query.WhereMatchesAny(techs);
        }

        return await query.Select(v => v.PublishedAt).ToListAsync(ct);
    }

    private async Task<List<DateTimeOffset>> EventTimesAsync(
        DateTimeOffset start,
        IReadOnlyList<Technology> techs,
        bool following,
        Expression<Func<VulnerabilityEvent, bool>> eventFilter,
        CancellationToken ct)
    {
        IQueryable<VulnerabilityEvent> query = db.VulnerabilityEvents
            .Where(e => e.EventAt >= start)
            .Where(eventFilter);
        if (following)
        {
            var matched = db.Vulnerabilities.WhereMatchesAny(techs);
            query = query.Where(e => matched.Any(v => v.Id == e.VulnerabilityId));
        }

        return await query.Select(e => e.EventAt).ToListAsync(ct);
    }
}
