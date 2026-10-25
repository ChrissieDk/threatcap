using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Services;

public record FollowedTechnologyDto(
    Guid Id,
    string Name,
    string Slug,
    string Type,
    string? Ecosystem,
    bool EcosystemWide,
    DateTimeOffset FollowedAt,
    int RecentActivityCount,
    int KevCount,
    int CriticalHighCount,
    DateTimeOffset? LastActivityAt);

public class FollowService(ThreatwatchDbContext db)
{
    public const int DefaultActivityDays = 7;

    private static readonly Regex SlugSanitize = new("[^a-z0-9]+", RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    public async Task<IReadOnlyList<FollowedTechnologyDto>> ListAsync(
        Guid userId,
        int activityDays,
        CancellationToken ct)
    {
        var follows = await db.UserFollows
            .AsNoTracking()
            .Where(f => f.UserId == userId)
            .Include(f => f.Technology)
            .ToListAsync(ct);

        if (follows.Count == 0)
        {
            return [];
        }

        var hits = await RecentPackageHitsAsync(activityDays, ct);
        return follows
            .Select(follow => ToDto(follow, hits))
            .OrderByDescending(item => item.LastActivityAt)
            .ThenByDescending(item => item.KevCount)
            .ThenByDescending(item => item.CriticalHighCount)
            .ThenByDescending(item => item.RecentActivityCount)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public Task<List<Technology>> ListFollowedTechnologiesAsync(Guid userId, CancellationToken ct) =>
        db.UserFollows
            .Where(f => f.UserId == userId)
            .Select(f => f.Technology)
            .ToListAsync(ct);

    public async Task<FollowedTechnologyDto?> FollowAsync(Guid userId, string slug, CancellationToken ct)
    {
        var technology = await FindTechnologyAsync(slug, ct);
        if (technology is null)
        {
            return null;
        }

        return await FollowTechnologyAsync(userId, technology, ct);
    }

    public async Task<FollowedTechnologyDto?> FollowPackageAsync(
        Guid userId,
        string ecosystem,
        string packageName,
        CancellationToken ct)
    {
        if (!Enum.TryParse<Ecosystem>(ecosystem, ignoreCase: true, out var eco))
        {
            return null;
        }

        var name = packageName.Trim();
        if (name.Length is 0 or > 128)
        {
            return null;
        }

        var catalog = await db.Technologies.ToListAsync(ct);
        var match = catalog.FirstOrDefault(t =>
            !TechnologyPackageMatcher.IsEcosystemWide(t)
            && TechnologyPackageMatcher.Matches(t, eco, name, name));

        if (match is null)
        {
            var slug = SlugForPackage(name);
            match = catalog.FirstOrDefault(t => t.Slug == slug);
            if (match is null)
            {
                match = new Technology
                {
                    Id = Guid.NewGuid(),
                    Name = name,
                    Slug = slug,
                    Type = TechnologyType.Package,
                    Ecosystem = eco,
                    Aliases = [],
                };
                db.Technologies.Add(match);
                await db.SaveChangesAsync(ct);
            }
        }

        return await FollowTechnologyAsync(userId, match, ct);
    }

    public async Task<bool> UnfollowAsync(Guid userId, string slug, CancellationToken ct)
    {
        var technology = await FindTechnologyAsync(slug, ct);
        if (technology is null)
        {
            return false;
        }

        var follow = await db.UserFollows
            .FirstOrDefaultAsync(f => f.UserId == userId && f.TechnologyId == technology.Id, ct);
        if (follow is not null)
        {
            db.UserFollows.Remove(follow);
            await db.SaveChangesAsync(ct);
        }

        return true;
    }

    private async Task<FollowedTechnologyDto> FollowTechnologyAsync(Guid userId, Technology technology, CancellationToken ct)
    {
        var existing = await db.UserFollows
            .Include(f => f.Technology)
            .FirstOrDefaultAsync(f => f.UserId == userId && f.TechnologyId == technology.Id, ct);
        if (existing is not null)
        {
            return ToDto(existing, await RecentPackageHitsAsync(DefaultActivityDays, ct));
        }

        var follow = new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TechnologyId = technology.Id,
            CreatedAt = DateTimeOffset.UtcNow,
            Technology = technology,
        };
        db.UserFollows.Add(follow);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            follow = await db.UserFollows
                .Include(f => f.Technology)
                .FirstAsync(f => f.UserId == userId && f.TechnologyId == technology.Id, ct);
        }

        return ToDto(follow, await RecentPackageHitsAsync(DefaultActivityDays, ct));
    }

    private Task<Technology?> FindTechnologyAsync(string slug, CancellationToken ct) =>
        db.Technologies.FirstOrDefaultAsync(t => t.Slug == slug, ct);

    private async Task<IReadOnlyList<PackageHit>> RecentPackageHitsAsync(int activityDays, CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-activityDays);
        return await db.AffectedPackages
            .AsNoTracking()
            .Where(p => p.Vulnerability.PublishedAt >= cutoff)
            .Select(p => new PackageHit(
                p.Ecosystem,
                p.PackageName,
                p.DisplayName,
                p.VulnerabilityId,
                p.Vulnerability.PublishedAt,
                p.Vulnerability.Severity,
                p.Vulnerability.IsKnownExploited))
            .ToListAsync(ct);
    }

    private static FollowedTechnologyDto ToDto(UserFollow follow, IReadOnlyList<PackageHit> hits)
    {
        var tech = follow.Technology;
        var matched = hits
            .Where(hit => TechnologyPackageMatcher.Matches(tech, hit.Ecosystem, hit.PackageName, hit.DisplayName))
            .ToList();
        var vulns = matched
            .GroupBy(hit => hit.VulnerabilityId)
            .Select(group => group.First())
            .ToList();

        return new FollowedTechnologyDto(
            tech.Id,
            tech.Name,
            tech.Slug,
            tech.Type.ToString(),
            tech.Ecosystem?.ToString(),
            TechnologyPackageMatcher.IsEcosystemWide(tech),
            follow.CreatedAt,
            vulns.Count,
            vulns.Count(hit => hit.IsKnownExploited),
            vulns.Count(hit => hit.Severity is Severity.Critical or Severity.High),
            vulns.Count == 0 ? null : vulns.Max(hit => hit.PublishedAt));
    }

    internal static string SlugForPackage(string packageName)
    {
        var slug = SlugSanitize.Replace(packageName.Trim().ToLowerInvariant(), "-").Trim('-');
        if (slug.Length == 0)
        {
            slug = "package";
        }

        if (!slug.StartsWith("pkg-", StringComparison.Ordinal))
        {
            slug = "pkg-" + slug;
        }

        return slug.Length > 80 ? slug[..80].TrimEnd('-') : slug;
    }

    private readonly record struct PackageHit(
        Ecosystem Ecosystem,
        string PackageName,
        string DisplayName,
        Guid VulnerabilityId,
        DateTimeOffset PublishedAt,
        Severity Severity,
        bool IsKnownExploited);
}
