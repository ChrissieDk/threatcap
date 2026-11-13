using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Projects;

public class TriageService(ThreatwatchDbContext db)
{
    public const int MaxSnoozeDays = 365;

    /// <summary>
    /// Records how a user is handling a finding. Returns an error message for invalid input, and
    /// <c>Found = false</c> when the project is not the user's or the advisory does not exist.
    /// </summary>
    public async Task<(string? Error, bool Found)> SetAsync(
        Guid userId, Guid projectId, Guid vulnerabilityId, TriageStatus status, int? snoozeDays, CancellationToken ct)
    {
        if (status == TriageStatus.Snoozed && snoozeDays is not (>= 1 and <= MaxSnoozeDays))
        {
            return ($"Snooze for between 1 and {MaxSnoozeDays} days.", true);
        }

        if (!await db.Projects.AnyAsync(p => p.Id == projectId && p.UserId == userId, ct)
            || !await db.Vulnerabilities.AnyAsync(v => v.Id == vulnerabilityId, ct))
        {
            return (null, false);
        }

        var now = DateTimeOffset.UtcNow;
        var row = await db.FindingTriages.FirstOrDefaultAsync(
            t => t.ProjectId == projectId && t.VulnerabilityId == vulnerabilityId, ct);
        if (row is null)
        {
            row = new FindingTriage { Id = Guid.NewGuid(), ProjectId = projectId, VulnerabilityId = vulnerabilityId };
            db.FindingTriages.Add(row);
        }

        row.Status = status;
        row.SnoozedUntil = status == TriageStatus.Snoozed ? now.AddDays(snoozeDays!.Value) : null;
        row.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        return (null, true);
    }

    /// <summary>Reopens a finding. Returns false if the project is not the user's.</summary>
    public async Task<bool> ClearAsync(Guid userId, Guid projectId, Guid vulnerabilityId, CancellationToken ct)
    {
        if (!await db.Projects.AnyAsync(p => p.Id == projectId && p.UserId == userId, ct)) return false;

        var row = await db.FindingTriages.FirstOrDefaultAsync(
            t => t.ProjectId == projectId && t.VulnerabilityId == vulnerabilityId, ct);
        if (row is not null)
        {
            db.FindingTriages.Remove(row);
            await db.SaveChangesAsync(ct);
        }

        return true;
    }

    /// <summary>
    /// Triage decisions that currently apply (a snooze stops applying once it expires),
    /// for every project of the given users.
    /// </summary>
    public static async Task<Dictionary<(Guid ProjectId, Guid VulnerabilityId), FindingTriage>> ActiveAsync(
        ThreatwatchDbContext db, IReadOnlyCollection<Guid> userIds, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var rows = await db.FindingTriages.AsNoTracking()
            .Where(t => userIds.Contains(t.Project.UserId)
                && (t.Status != TriageStatus.Snoozed || t.SnoozedUntil > now))
            .ToListAsync(ct);
        return rows.ToDictionary(t => (t.ProjectId, t.VulnerabilityId));
    }
}
