using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;

namespace Threatwatch.Core.Services;

public record TechnologyListItemDto(
    Guid Id,
    string Name,
    string Slug,
    string Type,
    string? Ecosystem,
    string[] Aliases,
    bool Following);

public class TechnologyQueryService(ThreatwatchDbContext db)
{
    public async Task<IReadOnlyList<TechnologyListItemDto>> ListAsync(string? search, Guid userId, CancellationToken ct)
    {
        var query = db.Technologies.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = $"%{search.Trim()}%";
            query = query.Where(t =>
                EF.Functions.ILike(t.Name, term)
                || EF.Functions.ILike(t.Slug, term)
                || t.Aliases.Any(a => EF.Functions.ILike(a, term)));
        }

        return await query
            .OrderBy(t => t.Name)
            .Select(t => new TechnologyListItemDto(
                t.Id, t.Name, t.Slug, t.Type.ToString(),
                t.Ecosystem.HasValue ? t.Ecosystem.Value.ToString() : null,
                t.Aliases,
                db.UserFollows.Any(f => f.UserId == userId && f.TechnologyId == t.Id)))
            .ToListAsync(ct);
    }

    public async Task<TechnologyListItemDto?> GetBySlugAsync(string slug, Guid userId, CancellationToken ct)
    {
        return await db.Technologies
            .Where(t => t.Slug == slug)
            .Select(t => new TechnologyListItemDto(
                t.Id, t.Name, t.Slug, t.Type.ToString(),
                t.Ecosystem.HasValue ? t.Ecosystem.Value.ToString() : null,
                t.Aliases,
                db.UserFollows.Any(f => f.UserId == userId && f.TechnologyId == t.Id)))
            .FirstOrDefaultAsync(ct);
    }
}
