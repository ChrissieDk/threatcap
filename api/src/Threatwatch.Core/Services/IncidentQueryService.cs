using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Services;

public record IncidentListItemDto(
    Guid Id,
    string Title,
    string? Description,
    IncidentType Type,
    IncidentStatus Status,
    string VendorSlug,
    string VendorName,
    Ecosystem? Ecosystem,
    string? Url,
    DateTimeOffset StartedAt,
    DateTimeOffset? ResolvedAt,
    DateTimeOffset UpdatedAt);

public class IncidentQueryService(ThreatwatchDbContext db, FollowService follows)
{
    public const int DefaultDays = 30;
    public const int DefaultLimit = 50;

    public async Task<IReadOnlyList<IncidentListItemDto>> ListAsync(
        int days,
        int limit,
        bool following,
        Guid userId,
        CancellationToken ct)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        IQueryable<SecurityIncident> query = db.SecurityIncidents.AsNoTracking();

        if (following)
        {
            var techs = await follows.ListFollowedTechnologiesAsync(userId, ct);
            query = query.WhereMatchesFollows(techs);
        }

        return await query
            .Where(i => i.Status != IncidentStatus.Resolved || i.StartedAt >= cutoff)
            .OrderBy(i => i.Status == IncidentStatus.Resolved ? 1 : 0)
            .ThenByDescending(i => i.UpdatedAt)
            .ThenByDescending(i => i.StartedAt)
            .Take(limit)
            .Select(i => new IncidentListItemDto(
                i.Id,
                i.Title,
                i.Description,
                i.Type,
                i.Status,
                i.VendorSlug,
                i.VendorName,
                i.Ecosystem,
                i.Url,
                i.StartedAt,
                i.ResolvedAt,
                i.UpdatedAt))
            .ToListAsync(ct);
    }
}
