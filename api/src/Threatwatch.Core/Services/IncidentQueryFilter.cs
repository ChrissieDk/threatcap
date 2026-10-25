using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Services;

public static class IncidentQueryFilter
{
    /// <summary>
    /// Vendor incidents that apply to the followed set: exact vendor slug
    /// (GitHub, Cloudflare, Docker) or shared ecosystem (npm, PyPI).
    /// </summary>
    public static IQueryable<SecurityIncident> WhereMatchesFollows(
        this IQueryable<SecurityIncident> query,
        IReadOnlyList<Technology> technologies)
    {
        if (technologies.Count == 0)
        {
            return query.Where(_ => false);
        }

        var slugs = technologies
            .Select(t => t.Slug)
            .Distinct()
            .ToArray();
        var ecosystems = technologies
            .Where(t => t.Ecosystem.HasValue)
            .Select(t => t.Ecosystem!.Value)
            .Distinct()
            .ToArray();

        if (ecosystems.Length == 0)
        {
            return query.Where(i => slugs.Contains(i.VendorSlug));
        }

        return query.Where(i =>
            slugs.Contains(i.VendorSlug)
            || (i.Ecosystem != null && ecosystems.Contains(i.Ecosystem.Value)));
    }
}
