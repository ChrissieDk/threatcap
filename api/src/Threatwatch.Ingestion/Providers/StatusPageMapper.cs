using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Ingestion.Providers;

public sealed record StatusPageVendor(
    string Slug,
    string Name,
    string IncidentsUrl,
    Ecosystem? Ecosystem);

/// <summary>
/// Maps Atlassian Statuspage incident JSON onto <see cref="SecurityIncident"/>.
/// Only public, unauthenticated feeds are used — no paid health APIs.
/// </summary>
public static class StatusPageMapper
{
    public const int MaxTitleLength = 300;
    public const int MaxDescriptionLength = 2000;

    /// <summary>
    /// Free public Statuspage JSON hosts. AWS Health and NuGet have no equivalent
    /// unauthenticated feed, so they are intentionally omitted.
    /// </summary>
    public static readonly IReadOnlyList<StatusPageVendor> Vendors =
    [
        new("github", "GitHub", "https://www.githubstatus.com/api/v2/incidents.json", null),
        new("npm", "npm", "https://status.npmjs.org/api/v2/incidents.json", Ecosystem.Npm),
        new("pypi", "PyPI", "https://status.python.org/api/v2/incidents.json", Ecosystem.PyPI),
        new("cloudflare", "Cloudflare", "https://www.cloudflarestatus.com/api/v2/incidents.json", null),
        new("docker", "Docker", "https://www.dockerstatus.com/api/v2/incidents.json", null),
    ];

    public static string ExternalId(string vendorSlug, string incidentId) =>
        $"{vendorSlug}:{incidentId}";

    public static IncidentStatus MapStatus(string? status, bool hasResolvedAt) =>
        (status ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "investigating" => IncidentStatus.Investigating,
            "identified" => IncidentStatus.Identified,
            "monitoring" => IncidentStatus.Monitoring,
            "resolved" or "postmortem" => IncidentStatus.Resolved,
            _ => hasResolvedAt ? IncidentStatus.Resolved : IncidentStatus.Investigating,
        };

    public static IncidentType MapType(string? impact, string title, string? description)
    {
        var haystack = $"{title}\n{description}".ToLowerInvariant();
        if (haystack.Contains("data breach", StringComparison.Ordinal)
            || haystack.Contains("security incident", StringComparison.Ordinal)
            || haystack.Contains("ransomware", StringComparison.Ordinal)
            || haystack.Contains("zero-day", StringComparison.Ordinal)
            || haystack.Contains("zeroday", StringComparison.Ordinal))
        {
            return IncidentType.SecurityIncident;
        }

        return (impact ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "critical" or "major" => IncidentType.Outage,
            _ => IncidentType.ServiceDegradation,
        };
    }

    public static DateTimeOffset ParseTime(string? value, DateTimeOffset fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return DateTimeOffset.TryParse(value, out var parsed) ? parsed.ToUniversalTime() : fallback;
    }

    public static string? LatestUpdateBody(StatusPageIncident incident)
    {
        var body = incident.IncidentUpdates
            .Select(u => u.Body)
            .FirstOrDefault(b => !string.IsNullOrWhiteSpace(b));
        return Truncate(body, MaxDescriptionLength);
    }

    public static string? IncidentUrl(StatusPageIncident incident, StatusPagePage page)
    {
        if (!string.IsNullOrWhiteSpace(incident.Shortlink))
        {
            return incident.Shortlink.Trim();
        }

        if (string.IsNullOrWhiteSpace(page.Url) || string.IsNullOrWhiteSpace(incident.Id))
        {
            return null;
        }

        return $"{page.Url.TrimEnd('/')}/incidents/{incident.Id}";
    }

    public static string TitleOf(StatusPageIncident incident) =>
        Truncate(string.IsNullOrWhiteSpace(incident.Name) ? "Vendor incident" : incident.Name.Trim(), MaxTitleLength)
        ?? "Vendor incident";

    public static void Apply(
        SecurityIncident target,
        StatusPageVendor vendor,
        StatusPagePage page,
        StatusPageIncident incident,
        DateTimeOffset now)
    {
        var description = LatestUpdateBody(incident);
        var resolvedAt = string.IsNullOrWhiteSpace(incident.ResolvedAt)
            ? (DateTimeOffset?)null
            : ParseTime(incident.ResolvedAt, now);

        target.Title = TitleOf(incident);
        target.Description = description;
        target.Type = MapType(incident.Impact, target.Title, description);
        target.Status = MapStatus(incident.Status, resolvedAt.HasValue);
        target.ResolvedAt = target.Status == IncidentStatus.Resolved ? resolvedAt ?? now : null;
        target.Url = IncidentUrl(incident, page);
        target.VendorSlug = vendor.Slug;
        target.VendorName = vendor.Name;
        target.Ecosystem = vendor.Ecosystem;
        target.SourceType = SourceType.StatusPage;
        target.UpdatedAt = now;
    }

    private static string? Truncate(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed.Length <= max ? trimmed : trimmed[..max];
    }
}
