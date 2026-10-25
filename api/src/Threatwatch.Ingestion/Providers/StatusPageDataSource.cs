using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Normalization;

namespace Threatwatch.Ingestion.Providers;

/// <summary>
/// Pulls recent incidents from public Atlassian Statuspage JSON endpoints.
/// No API key and no paid vendor-health APIs.
/// </summary>
public class StatusPageDataSource(
    HttpClient httpClient,
    ILogger<StatusPageDataSource> logger) : ISecurityDataSource
{
    public string Name => "statuspage";
    public IngestionSource Source => IngestionSource.StatusPage;
    public TimeSpan Interval => TimeSpan.FromMinutes(15);

    public async Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct)
    {
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        await IngestionStateHelper.GetOrCreateAsync(db, Source, ct);

        var existing = await db.SecurityIncidents
            .Where(i => i.SourceType == SourceType.StatusPage)
            .ToListAsync(ct);
        var byExternalId = existing.ToDictionary(i => i.ExternalId, StringComparer.Ordinal);

        var processed = 0;
        var feedsOk = 0;
        var errors = new List<string>();
        DateTimeOffset? newest = null;
        var now = DateTimeOffset.UtcNow;

        foreach (var vendor in StatusPageMapper.Vendors)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var response = await httpClient.GetAsync(vendor.IncidentsUrl, ct);
                if (!response.IsSuccessStatusCode)
                {
                    errors.Add($"{vendor.Slug}: HTTP {(int)response.StatusCode}");
                    logger.LogWarning(
                        "Statuspage '{Vendor}' returned {Status}.",
                        vendor.Slug, (int)response.StatusCode);
                    continue;
                }

                var json = await response.Content.ReadAsStringAsync(ct);
                var feed = OsvJsonReader.Deserialize<StatusPageFeedResponse>(json);
                if (feed is null)
                {
                    errors.Add($"{vendor.Slug}: invalid JSON");
                    continue;
                }

                feedsOk++;
                newest = MaxTime(newest, StatusPageMapper.ParseTime(feed.Page.UpdatedAt, now));

                foreach (var incident in feed.Incidents)
                {
                    ct.ThrowIfCancellationRequested();
                    if (string.IsNullOrWhiteSpace(incident.Id))
                    {
                        continue;
                    }

                    var externalId = StatusPageMapper.ExternalId(vendor.Slug, incident.Id);
                    if (!byExternalId.TryGetValue(externalId, out var row))
                    {
                        var started = StatusPageMapper.ParseTime(
                            incident.StartedAt ?? incident.CreatedAt, now);
                        row = new SecurityIncident
                        {
                            Id = Guid.NewGuid(),
                            ExternalId = externalId,
                            VendorSlug = vendor.Slug,
                            VendorName = vendor.Name,
                            Title = StatusPageMapper.TitleOf(incident),
                            StartedAt = started,
                            CreatedAt = now,
                            UpdatedAt = now,
                        };
                        db.SecurityIncidents.Add(row);
                        byExternalId[externalId] = row;
                    }

                    StatusPageMapper.Apply(row, vendor, feed.Page, incident, now);
                    processed++;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                errors.Add($"{vendor.Slug}: {ex.Message}");
                logger.LogWarning(ex, "Statuspage '{Vendor}' failed.", vendor.Slug);
            }
        }

        await db.SaveChangesAsync(ct);

        if (feedsOk == 0)
        {
            return IngestionResult.Failure(errors.Count == 0
                ? "No status page feeds were processed."
                : string.Join("; ", errors));
        }

        if (errors.Count > 0)
        {
            logger.LogWarning(
                "Statuspage sync finished with {Count} feed errors: {Errors}",
                errors.Count, string.Join("; ", errors));
        }

        logger.LogInformation("Statuspage sync upserted {Count} incidents.", processed);
        return IngestionResult.Success(processed, (newest ?? now).ToString("O"));
    }

    private static DateTimeOffset? MaxTime(DateTimeOffset? current, DateTimeOffset candidate) =>
        current is { } value && value > candidate ? value : candidate;
}
