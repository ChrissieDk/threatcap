using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;

namespace Threatwatch.Ingestion.Providers;

public class OsvOptions
{
    /// <summary>Only ingest advisories modified within this many days. Older history is left in the source.</summary>
    public int RetentionDays { get; set; } = 90;

    /// <summary>
    /// GCS prefixes under gs://osv-vulnerabilities. Rust advisories are published as
    /// <c>crates.io</c>, which <see cref="Normalization.PackageNameNormalizer"/> maps to the Cargo ecosystem.
    /// </summary>
    public string[] Ecosystems { get; set; } = ["npm", "NuGet", "PyPI", "Maven", "crates.io", "Go"];
}

/// <summary>
/// Synchronizes OSV.dev records via the official public data-export bucket
/// (gs://osv-vulnerabilities, served over HTTPS by GCS). The /v1/query API does not
/// support bulk "modified since" enumeration, so each run lists bucket objects and
/// downloads only those whose GCS "updated" timestamp is inside the retention window
/// (default 90 days) and newer than the stored watermark.
///
/// Records can also be ingested from a local directory via <see cref="OsvBackfillService"/>
/// (env OSV_BACKFILL_DIR), which is the same JSON format.
/// </summary>
public class OsvDataSource(
    HttpClient httpClient,
    IOptions<OsvOptions> options,
    ILogger<OsvDataSource> logger) : ISecurityDataSource
{
    private const string BucketObjectUrl = "/osv-vulnerabilities/";
    private const string BucketListUrl = "/storage/v1/b/osv-vulnerabilities/o";
    private const int ProgressInterval = 500;

    /// <summary>
    /// Escape each path segment. Encoding the whole object name would turn
    /// <c>npm/GHSA-….json</c> into <c>npm%2FGHSA-….json</c>, which GCS does not serve.
    /// </summary>
    private static string ObjectUrl(string objectName)
    {
        var encoded = string.Join('/',
            objectName.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Uri.EscapeDataString));
        return BucketObjectUrl + encoded;
    }

    public string Name => "osv";
    public IngestionSource Source => IngestionSource.Osv;
    public TimeSpan Interval => TimeSpan.FromHours(1);

    public async Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct)
    {
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var upserter = scope.ServiceProvider.GetRequiredService<VulnerabilityUpserter>();

        var state = await IngestionStateHelper.GetOrCreateAsync(db, Source, ct);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-Math.Max(1, options.Value.RetentionDays));
        var storedWatermark = state.WatermarkParsed();
        var watermark = storedWatermark is { } stored && stored >= cutoff ? stored : cutoff;

        var processed = 0;
        var skipped = 0;
        var maxSeen = watermark;

        foreach (var ecosystem in options.Value.Ecosystems)
        {
            ct.ThrowIfCancellationRequested();
            logger.LogInformation(
                "OSV sync: listing {Ecosystem} objects updated after {Watermark}.", ecosystem, watermark);

            var changed = await ListChangedRecordsAsync(ecosystem, watermark, ct);
            logger.LogInformation(
                "OSV sync: {Ecosystem} has {Count} objects in the retention window.", ecosystem, changed.Count);

            foreach (var obj in changed)
            {
                ct.ThrowIfCancellationRequested();
                if (DateTimeOffset.TryParse(obj.Updated, out var updated) && updated > maxSeen)
                {
                    maxSeen = updated;
                }

                try
                {
                    var record = await httpClient.GetFromJsonAsync<OsvRecord>(ObjectUrl(obj.Name), ct);
                    if (record is null)
                    {
                        continue;
                    }

                    if (!IsWithinRetention(record, cutoff))
                    {
                        skipped++;
                        continue;
                    }

                    await upserter.UpsertOsvRecordAsync(record, ct);
                    processed++;
                    if (processed % ProgressInterval == 0)
                    {
                        logger.LogInformation("OSV sync imported {Count} records so far.", processed);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "Failed to ingest OSV record {Name}; continuing.", obj.Name);
                }
            }
        }

        logger.LogInformation(
            "OSV sync processed {Count} records, skipped {Skipped} outside the {Days}-day window (watermark {Watermark}).",
            processed, skipped, options.Value.RetentionDays, maxSeen);
        return IngestionResult.Success(processed, maxSeen.ToString("O"));
    }

    private static bool IsWithinRetention(OsvRecord record, DateTimeOffset cutoff)
    {
        var activity = record.ModifiedParsed ?? record.PublishedParsed;
        return activity is not null && activity >= cutoff;
    }

    private async Task<List<GcsObject>> ListChangedRecordsAsync(
        string ecosystem, DateTimeOffset watermark, CancellationToken ct)
    {
        var result = new List<GcsObject>();
        string? pageToken = null;

        do
        {
            ct.ThrowIfCancellationRequested();

            var url = BucketListUrl
                + $"?prefix={Uri.EscapeDataString(ecosystem + "/")}"
                + "&fields=items(name,updated),nextPageToken"
                + "&pageSize=1000"
                + (pageToken is not null ? $"&pageToken={Uri.EscapeDataString(pageToken)}" : string.Empty);

            var listing = await httpClient.GetFromJsonAsync<GcsListing>(url, ct);
            if (listing?.Items is null)
            {
                break;
            }

            foreach (var item in listing.Items)
            {
                if (item.Name.EndsWith("/all.zip", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (DateTimeOffset.TryParse(item.Updated, out var updated) && updated > watermark)
                {
                    result.Add(item);
                }
            }

            pageToken = listing.NextPageToken;
        }
        while (!string.IsNullOrEmpty(pageToken));

        return result;
    }
}

public sealed class GcsListing
{
    [JsonPropertyName("items")] public List<GcsObject>? Items { get; set; }
    [JsonPropertyName("nextPageToken")] public string? NextPageToken { get; set; }
}

public sealed class GcsObject
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("updated")] public string? Updated { get; set; }
}

public static class IngestionStateHelper
{
    public static DateTimeOffset? WatermarkParsed(this Core.Entities.IngestionState state)
        => DateTimeOffset.TryParse(state.Watermark, out var dto) ? dto : null;

    public static async Task<Core.Entities.IngestionState> GetOrCreateAsync(
        ThreatwatchDbContext db, IngestionSource source, CancellationToken ct)
    {
        var state = await db.IngestionStates.FirstOrDefaultAsync(s => s.Source == source, ct);
        if (state is null)
        {
            state = new Core.Entities.IngestionState
            {
                Id = Guid.NewGuid(),
                Source = source,
            };
            db.IngestionStates.Add(state);
            await db.SaveChangesAsync(ct);
        }

        return state;
    }
}
