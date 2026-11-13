using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Projects;

namespace Threatwatch.Core.Services;

public record NotificationItemDto(
    Guid VulnerabilityId,
    string CanonicalId,
    string Title,
    Severity Severity,
    decimal? CvssScore,
    bool IsKnownExploited,
    DateTimeOffset ActivityAt,
    string MatchedTechnologyName,
    string MatchedTechnologySlug,
    bool IsNew = true,
    string? Reason = null);

public record NotificationSummaryDto(
    int UnreadCount,
    bool HasKevUnread,
    IReadOnlyList<NotificationItemDto> Items,
    DateTimeOffset GeneratedAt,
    int TotalRelevant = 0);

/// <summary>
/// In-app notifications, derived at read time so reprocessing source data can never create
/// duplicates. An item is relevant when it matches the user's projects (version-checked) or a
/// followed technology AND passes the user's alert rules (or the defaults: High and above, plus
/// anything actively exploited). Following a whole ecosystem is a firehose, so those matches only
/// count when the advisory is actively exploited or Critical. "New" means newer than the read cursor
/// (<see cref="UserAccount.LastNotificationsReadAt"/>); the list is ranked by importance and capped.
/// </summary>
public class NotificationService(ThreatwatchDbContext db)
{
    public const int DefaultLookbackDays = 14;
    public const int MaxItems = 10;

    private static readonly AlertPreference DefaultRules = new()
    {
        MinSeverity = Severity.High,
        AlwaysAlertKnownExploited = true,
    };

    public async Task<NotificationSummaryDto> GetAsync(Guid userId, CancellationToken ct)
    {
        var user = await db.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return Empty();
        }

        var follows = await db.UserFollows
            .AsNoTracking()
            .Where(f => f.UserId == userId)
            .Select(f => f.Technology)
            .ToListAsync(ct);
        var deps = (await ProjectService.LoadMergedAsync(db, [userId], ct)).GetValueOrDefault(userId) ?? [];
        var triaged = await TriageService.ActiveAsync(db, [userId], ct);
        if (follows.Count == 0 && deps.Count == 0)
        {
            return Empty();
        }

        var rules = await db.AlertPreferences.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == userId, ct) ?? DefaultRules;
        var depIndex = deps.ToLookup(d => (d.Ecosystem, d.Name));
        var cursor = user.LastNotificationsReadAt;
        var windowStart = DateTimeOffset.UtcNow.AddDays(-DefaultLookbackDays);

        // Vulnerabilities recently published OR recently added to CISA KEV.
        var recentVulns = await db.Vulnerabilities
            .AsNoTracking()
            .Where(v => !v.IsWithdrawn
                && (v.PublishedAt >= windowStart
                    || v.Events.Any(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded
                        && e.EventAt >= windowStart)))
            .Select(v => new
            {
                v.Id,
                v.CanonicalId,
                v.Title,
                v.Severity,
                v.CvssScore,
                v.EpssScore,
                v.IsKnownExploited,
                v.PublishedAt,
                Packages = v.AffectedPackages
                    .Select(p => new { p.Ecosystem, p.PackageName, p.DisplayName, p.AffectedRanges })
                    .ToList(),
                KevAddedAt = v.Events
                    .Where(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded)
                    .Select(e => (DateTimeOffset?)e.EventAt)
                    .FirstOrDefault(),
            })
            .ToListAsync(ct);

        var relevant = new List<(int Rank, NotificationItemDto Item)>();
        foreach (var vuln in recentVulns)
        {
            var activityAt = vuln.KevAddedAt > vuln.PublishedAt ? vuln.KevAddedAt!.Value : vuln.PublishedAt;

            // 1. Version-checked hit in one of the user's projects: always worth knowing.
            string? reason = null;
            foreach (var p in vuln.Packages)
            {
                foreach (var dep in depIndex[(p.Ecosystem, p.PackageName)])
                {
                    if (triaged.ContainsKey((dep.ProjectId, vuln.Id))) continue;
                    var check = OsvRangeEvaluator.Evaluate(p.Ecosystem, p.AffectedRanges, dep.Version);
                    if (check.Verdict != RangeVerdict.Affected) continue;
                    reason = $"Affects {dep.ProjectName}: {dep.DisplayName} {dep.Version}"
                        + (check.FixedIn is null ? "" : $" (fixed in {check.FixedIn})");
                    break;
                }

                if (reason is not null) break;
            }

            Technology? matched = null;
            if (reason is null)
            {
                // 2. Followed technology, preferring a specific follow over an ecosystem-wide one.
                var matches = follows.Where(t => vuln.Packages.Any(pkg =>
                    TechnologyPackageMatcher.Matches(t, pkg.Ecosystem, pkg.PackageName, pkg.DisplayName))).ToList();
                matched = matches.FirstOrDefault(t => !TechnologyPackageMatcher.IsEcosystemWide(t)) ?? matches.FirstOrDefault();
                if (matched is null) continue;

                var passes = TechnologyPackageMatcher.IsEcosystemWide(matched)
                    ? vuln.IsKnownExploited || vuln.Severity == Severity.Critical
                    : AlertService.Passes(rules, vuln.Severity, vuln.IsKnownExploited, vuln.EpssScore);
                if (!passes) continue;
                reason = $"Affects {matched.Name}";
            }

            var rank = (vuln.IsKnownExploited ? 1000 : 0) + (matched is null ? 500 : 0) + (int)vuln.Severity * 100;
            relevant.Add((rank, new NotificationItemDto(
                vuln.Id,
                vuln.CanonicalId,
                vuln.Title,
                vuln.Severity,
                vuln.CvssScore,
                vuln.IsKnownExploited,
                activityAt,
                matched?.Name ?? reason!,
                matched?.Slug ?? string.Empty,
                IsNew: cursor is null || activityAt > cursor.Value,
                Reason: reason)));
        }

        var ordered = relevant
            .OrderByDescending(r => r.Item.IsNew)
            .ThenByDescending(r => r.Rank)
            .ThenByDescending(r => r.Item.ActivityAt)
            .Select(r => r.Item)
            .ToList();
        var top = ordered.Take(MaxItems).ToList();
        var newItems = ordered.Where(i => i.IsNew).ToList();

        return new NotificationSummaryDto(
            newItems.Count,
            newItems.Any(i => i.IsKnownExploited),
            top,
            DateTimeOffset.UtcNow,
            ordered.Count);
    }

    private static NotificationSummaryDto Empty() => new(0, false, [], DateTimeOffset.UtcNow);

    public async Task<NotificationSummaryDto> MarkAllReadAsync(Guid userId, CancellationToken ct)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return new NotificationSummaryDto(0, false, [], DateTimeOffset.UtcNow);
        }

        user.LastNotificationsReadAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return await GetAsync(userId, ct);
    }
}
