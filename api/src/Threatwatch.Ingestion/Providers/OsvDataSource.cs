using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
/// (gs://osv-vulnerabilities, served over HTTPS by GCS). Each run downloads the
/// per-ecosystem <c>{ecosystem}/all.zip</c> archive — one request containing every
/// record as an individual JSON entry — and upserts the records whose
/// <c>modified</c> timestamp is inside the retention window (default 90 days) and
/// newer than the stored watermark. Ecosystems are processed in parallel with a
/// bounded degree of parallelism; each parallel branch runs in its own DI scope
/// because EF Core contexts are not thread-safe. If the archive download fails for
/// an ecosystem, that ecosystem alone falls back to listing bucket objects and
/// downloading each changed record individually.
///
/// Records can also be ingested from a local directory via <see cref="OsvBackfillService"/>
/// (env OSV_BACKFILL_DIR), which is the same JSON format.
/// </summary>
public class OsvDataSource(
    HttpClient httpClient,
    IOptions<OsvOptions> options,
    IServiceScopeFactory scopeFactory,
    ILogger<OsvDataSource> logger) : ISecurityDataSource
{
    private const string BucketObjectUrl = "/osv-vulnerabilities/";
    private const string BucketListUrl = "/storage/v1/b/osv-vulnerabilities/o";
    private const int ProgressInterval = 500;
    private const int MaxParallelEcosystems = 3;

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

        var state = await IngestionStateHelper.GetOrCreateAsync(db, Source, ct);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-Math.Max(1, options.Value.RetentionDays));
        var storedWatermark = state.WatermarkParsed();
        var watermark = storedWatermark is { } stored && stored >= cutoff ? stored : cutoff;

        using var semaphore = new SemaphoreSlim(MaxParallelEcosystems);
        var branches = options.Value.Ecosystems.Select(async ecosystem =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                return await SyncEcosystemAsync(ecosystem, watermark, cutoff, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "OSV sync: ecosystem {Ecosystem} failed; continuing with the others.", ecosystem);
                return new EcosystemResult(0, 0, watermark);
            }
            finally
            {
                semaphore.Release();
            }
        });

        var results = await Task.WhenAll(branches);
        var processed = results.Sum(r => r.Processed);
        var skipped = results.Sum(r => r.Skipped);
        var maxSeen = results.Select(r => r.MaxSeen).DefaultIfEmpty(watermark).Max();

        logger.LogInformation(
            "OSV sync processed {Count} records, skipped {Skipped} outside the {Days}-day window or older than the watermark (watermark {Watermark}).",
            processed, skipped, options.Value.RetentionDays, maxSeen);
        return IngestionResult.Success(processed, maxSeen.ToString("O"));
    }

    private async Task<EcosystemResult> SyncEcosystemAsync(
        string ecosystem, DateTimeOffset watermark, DateTimeOffset cutoff, CancellationToken ct)
    {
        // Each parallel branch resolves its own scoped services; the incoming scope
        // (and its DbContext) is not safe to share across worker threads.
        await using var branchScope = scopeFactory.CreateAsyncScope();
        var upserter = branchScope.ServiceProvider.GetRequiredService<VulnerabilityUpserter>();

        logger.LogInformation(
            "OSV sync: downloading {Ecosystem}/all.zip modified after {Watermark}.", ecosystem, watermark);

        var zipPath = await DownloadAllZipAsync(ecosystem, ct);
        if (zipPath is not null)
        {
            try
            {
                return await ProcessAllZipAsync(ecosystem, zipPath, watermark, cutoff, upserter, ct);
            }
            catch (InvalidDataException ex)
            {
                logger.LogWarning(ex, "OSV sync: {Ecosystem}/all.zip is corrupt; falling back to listing.", ecosystem);
            }
            finally
            {
                TryDeleteTempFile(zipPath);
            }
        }

        logger.LogWarning(
            "OSV sync: {Ecosystem}/all.zip unavailable; falling back to object listing.", ecosystem);
        return await SyncEcosystemByListingAsync(ecosystem, watermark, cutoff, upserter, ct);
    }

    /// <summary>Stream the archive to a temp file; ZipArchive requires a seekable stream.</summary>
    private async Task<string?> DownloadAllZipAsync(string ecosystem, CancellationToken ct)
    {
        var tempPath = Path.GetTempFileName();
        try
        {
            using var response = await httpClient.GetAsync(
                BucketObjectUrl + Uri.EscapeDataString(ecosystem) + "/all.zip",
                HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                TryDeleteTempFile(tempPath);
                return null;
            }

            response.EnsureSuccessStatusCode();
            await using (var file = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                await response.Content.CopyToAsync(file, ct);
            }

            return tempPath;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "OSV sync: failed to download {Ecosystem}/all.zip.", ecosystem);
            TryDeleteTempFile(tempPath);
            return null;
        }
    }

    private async Task<EcosystemResult> ProcessAllZipAsync(
        string ecosystem, string zipPath, DateTimeOffset watermark, DateTimeOffset cutoff,
        VulnerabilityUpserter upserter, CancellationToken ct)
    {
        var processed = 0;
        var skipped = 0;
        var maxSeen = watermark;

        await using var file = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(file, ZipArchiveMode.Read);

        logger.LogInformation(
            "OSV sync: {Ecosystem} archive has {Count} entries.", ecosystem, archive.Entries.Count);

        foreach (var entry in archive.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (entry.Length == 0 || !entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                await using var entryStream = entry.Open();
                var record = await JsonSerializer.DeserializeAsync<OsvRecord>(entryStream, cancellationToken: ct);
                if (record is null)
                {
                    continue;
                }

                // Zip entries don't carry per-object GCS "updated" metadata, so the
                // record's own "modified" timestamp is the only watermark signal.
                var modified = record.ModifiedParsed;
                if (modified is not { } seen || seen <= watermark)
                {
                    skipped++;
                    continue;
                }

                if (!IsWithinRetention(record, cutoff))
                {
                    skipped++;
                    continue;
                }

                await upserter.UpsertOsvRecordAsync(record, ct);
                processed++;
                if (seen > maxSeen)
                {
                    maxSeen = seen;
                }

                if (processed % ProgressInterval == 0)
                {
                    logger.LogInformation("OSV sync imported {Count} records so far.", processed);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Failed to ingest OSV archive entry {Name}; continuing.", entry.FullName);
            }
        }

        return new EcosystemResult(processed, skipped, maxSeen);
    }

    private async Task<EcosystemResult> SyncEcosystemByListingAsync(
        string ecosystem, DateTimeOffset watermark, DateTimeOffset cutoff,
        VulnerabilityUpserter upserter, CancellationToken ct)
    {
        var processed = 0;
        var skipped = 0;
        var maxSeen = watermark;

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

        return new EcosystemResult(processed, skipped, maxSeen);
    }

    private static bool IsWithinRetention(OsvRecord record, DateTimeOffset cutoff)
    {
        var activity = record.ModifiedParsed ?? record.PublishedParsed;
        return activity is not null && activity >= cutoff;
    }

    private static void TryDeleteTempFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best-effort cleanup; the OS reclaims temp files eventually.
        }
    }

    private async Task<List<GcsObject>> ListChangedRecordsAsync(
        string ecosystem, DateTimeOffset watermark, CancellationToken ct)
    {
        var result = new List<GcsObject>();
        string? pageToken = null;
        var pages = 0;

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

            pages++;
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

            if (pages % 10 == 0)
            {
                logger.LogInformation(
                    "OSV sync: listed {Pages} {Ecosystem} pages, {Changed} objects newer than the watermark.",
                    pages, ecosystem, result.Count);
            }

            pageToken = listing.NextPageToken;
        }
        while (!string.IsNullOrEmpty(pageToken));

        return result;
    }

    private readonly record struct EcosystemResult(int Processed, int Skipped, DateTimeOffset MaxSeen);
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
