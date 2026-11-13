using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;

namespace Threatwatch.Core.Services;

/// <summary>Counts of what the instance has picked up, for the signed-out landing page.</summary>
public record PublicStatsDto(int VulnerabilitiesPickedUp, DateTimeOffset? Since);

public class PublicStatsService(ThreatwatchDbContext db)
{
    /// <summary>
    /// Advisories first ingested on or after <paramref name="since"/>. Without a date it counts everything
    /// and reports the day the first advisory was ingested.
    /// </summary>
    public async Task<PublicStatsDto> GetAsync(DateTimeOffset? since, CancellationToken ct)
    {
        var query = db.Vulnerabilities.Where(v => !v.IsWithdrawn);
        if (since is { } from)
        {
            query = query.Where(v => v.CreatedAt >= from);
            return new PublicStatsDto(await query.CountAsync(ct), from);
        }

        var count = await query.CountAsync(ct);
        DateTimeOffset? first = count == 0 ? null : await query.MinAsync(v => v.CreatedAt, ct);
        return new PublicStatsDto(count, first);
    }
}
