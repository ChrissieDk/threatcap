using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

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
    string MatchedTechnologySlug);

public record NotificationSummaryDto(
    int UnreadCount,
    bool HasKevUnread,
    IReadOnlyList<NotificationItemDto> Items,
    DateTimeOffset GeneratedAt);

/// <summary>
/// In-app notifications derived from the read cursor on UserAccount: unread activity is
/// any vulnerability matching a followed technology whose publication (or KEV addition)
/// happened after <see cref="UserAccount.LastNotificationsReadAt"/>. Derived at read time
/// rather than materialized during ingestion, so reprocessing source data can never
/// create duplicate notifications.
/// </summary>
public class NotificationService(ThreatwatchDbContext db)
{
    public const int DefaultLookbackDays = 14;
    public const int MaxItems = 20;

    public async Task<NotificationSummaryDto> GetAsync(Guid userId, CancellationToken ct)
    {
        var user = await db.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            return new NotificationSummaryDto(0, false, [], DateTimeOffset.UtcNow);
        }

        var follows = await db.UserFollows
            .AsNoTracking()
            .Where(f => f.UserId == userId)
            .Select(f => f.Technology)
            .ToListAsync(ct);

        if (follows.Count == 0)
        {
            return new NotificationSummaryDto(0, false, [], DateTimeOffset.UtcNow);
        }

        var hasCursor = user.LastNotificationsReadAt.HasValue;
        var lookbackStart = user.LastNotificationsReadAt ?? DateTimeOffset.UtcNow.AddDays(-DefaultLookbackDays);

        // Vulnerabilities recently published OR recently added to CISA KEV.
        var recentVulns = await db.Vulnerabilities
            .AsNoTracking()
            .Where(v =>
                v.PublishedAt >= lookbackStart
                || v.Events.Any(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded
                    && e.EventAt >= lookbackStart))
            .Select(v => new
            {
                v.Id,
                v.CanonicalId,
                v.Title,
                v.Severity,
                v.CvssScore,
                v.IsKnownExploited,
                v.PublishedAt,
                Packages = v.AffectedPackages
                    .Select(p => new { p.Ecosystem, p.PackageName, p.DisplayName })
                    .ToList(),
                KevAddedAt = v.Events
                    .Where(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded)
                    .Select(e => (DateTimeOffset?)e.EventAt)
                    .FirstOrDefault(),
            })
            .ToListAsync(ct);

        var items = new List<(DateTimeOffset ActivityAt, NotificationItemDto Item)>();
        foreach (var vuln in recentVulns)
        {
            var activityAt = vuln.KevAddedAt > lookbackStart && vuln.KevAddedAt > vuln.PublishedAt
                ? vuln.KevAddedAt!.Value
                : vuln.PublishedAt;

            foreach (var tech in follows)
            {
                var matched = vuln.Packages.Any(pkg =>
                    TechnologyPackageMatcher.Matches(tech, pkg.Ecosystem, pkg.PackageName, pkg.DisplayName));
                if (!matched)
                {
                    continue;
                }

                items.Add((activityAt, new NotificationItemDto(
                    vuln.Id,
                    vuln.CanonicalId,
                    vuln.Title,
                    vuln.Severity,
                    vuln.CvssScore,
                    vuln.IsKnownExploited,
                    activityAt,
                    tech.Name,
                    tech.Slug)));
                break; // one entry per vulnerability; first matched follow wins
            }
        }

        var top = items
            .OrderByDescending(i => i.ActivityAt)
            .Take(MaxItems)
            .Select(i => i.Item)
            .ToList();

        var unread = hasCursor
            ? items.Count(i => i.ActivityAt > user.LastNotificationsReadAt!.Value)
            : items.Count;

        return new NotificationSummaryDto(
            unread,
            top.Any(i => i.IsKnownExploited),
            top,
            DateTimeOffset.UtcNow);
    }

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
