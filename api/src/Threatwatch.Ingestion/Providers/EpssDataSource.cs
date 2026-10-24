using System.Globalization;
using System.IO.Compression;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;

namespace Threatwatch.Ingestion.Providers;

public class EpssOptions
{
    /// <summary>Path of the daily gzipped EPSS CSV, relative to the provider base address.</summary>
    public string FeedPath { get; set; } = "epss_scores-current.csv.gz";

    /// <summary>Hours between EPSS syncs. EPSS republishes the current CSV once per day.</summary>
    public int IntervalHours { get; set; } = 24;
}

/// <summary>
/// Synchronizes EPSS (Exploit Prediction Scoring System) scores from the daily
/// gzipped CSV at epss.empiricalsecurity.com. The file covers every published CVE,
/// so rows are filtered to CVEs the database already knows (canonical ids + CVE
/// aliases) before touching the upserter.
/// </summary>
public class EpssDataSource(
    HttpClient httpClient,
    IOptions<EpssOptions> options,
    ILogger<EpssDataSource> logger) : ISecurityDataSource
{
    public string Name => "epss";
    public IngestionSource Source => IngestionSource.Epss;
    public TimeSpan Interval => TimeSpan.FromHours(Math.Max(1, options.Value.IntervalHours));

    public async Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct)
    {
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var upserter = scope.ServiceProvider.GetRequiredService<VulnerabilityUpserter>();

        await IngestionStateHelper.GetOrCreateAsync(db, Source, ct);

        var knownCves = await db.VulnerabilityAliases
            .Where(a => a.AliasType == AliasType.Cve)
            .Select(a => a.Alias)
            .ToListAsync(ct);
        knownCves.AddRange(await db.Vulnerabilities
            .Where(v => v.CanonicalId.StartsWith("CVE-"))
            .Select(v => v.CanonicalId)
            .ToListAsync(ct));

        if (knownCves.Count == 0)
        {
            logger.LogInformation("EPSS sync: no CVEs in the database yet; nothing to update.");
            return IngestionResult.Success(0, DateTimeOffset.UtcNow.ToString("O"));
        }

        var wanted = new HashSet<string>(knownCves, StringComparer.OrdinalIgnoreCase);
        var scores = new Dictionary<string, (double Score, double Percentile)>(wanted.Count, StringComparer.OrdinalIgnoreCase);

        using var response = await httpClient.GetAsync(options.Value.FeedPath, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        await using var raw = await response.Content.ReadAsStreamAsync(ct);
        await using var gzip = new GZipStream(raw, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip);

        var scanned = 0;
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) is not null)
        {
            ct.ThrowIfCancellationRequested();
            scanned++;
            if (line.Length == 0 || line[0] == '#' || line.StartsWith("cve,", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = line.Split(',');
            if (parts.Length < 3 || !wanted.Contains(parts[0]))
            {
                continue;
            }

            if (!double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var epss)
                || !double.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var percentile))
            {
                continue;
            }

            scores[parts[0]] = (epss, percentile);
        }

        var updated = 0;
        foreach (var (cve, (epss, percentile)) in scores)
        {
            ct.ThrowIfCancellationRequested();
            if (await upserter.UpdateEpssAsync(cve, epss, percentile, ct))
            {
                updated++;
            }
        }

        logger.LogInformation(
            "EPSS sync scanned {Scanned} rows, applied scores to {Updated} known CVEs.", scanned, updated);
        return IngestionResult.Success(updated, DateTimeOffset.UtcNow.ToString("O"));
    }
}
