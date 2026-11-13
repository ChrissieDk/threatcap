using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;

namespace Threatwatch.Ingestion.Providers;

public class NvdOptions
{
    /// <summary>Turn NVD enrichment off entirely.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Minutes between enrichment passes.</summary>
    public int IntervalMinutes { get; set; } = 30;

    /// <summary>Most CVEs looked up per pass. Keeps a pass within NVD's public rate limit.</summary>
    public int MaxPerRun { get; set; } = 10;

    /// <summary>Only advisories modified within this many days are considered.</summary>
    public int LookbackDays { get; set; } = 30;

    /// <summary>Optional free NVD API key (raises the rate limit from 5 to 50 requests per 30 seconds).</summary>
    public string? ApiKey { get; set; }
}

/// <summary>
/// Enriches advisories that arrived without a CVSS rating (for example CVEs first seen through CISA KEV)
/// with the score NVD publishes. One request per CVE, paced to NVD's public rate limit. A rotating cursor
/// (the ingestion watermark) walks the candidates newest to oldest, so CVEs NVD has not analysed yet
/// cannot starve the rest; once the end is reached it starts again from the newest.
/// </summary>
public class NvdDataSource(
    HttpClient httpClient,
    IOptions<NvdOptions> options,
    ILogger<NvdDataSource> logger) : ISecurityDataSource
{
    public string Name => "nvd";
    public IngestionSource Source => IngestionSource.Nvd;
    public TimeSpan Interval => TimeSpan.FromMinutes(Math.Max(5, options.Value.IntervalMinutes));

    public async Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct)
    {
        var opts = options.Value;
        if (!opts.Enabled)
        {
            return IngestionResult.Success(0, null);
        }

        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var upserter = scope.ServiceProvider.GetRequiredService<VulnerabilityUpserter>();
        var cursor = (await IngestionStateHelper.GetOrCreateAsync(db, Source, ct)).WatermarkParsed();
        var cutoff = DateTimeOffset.UtcNow.AddDays(-Math.Max(1, opts.LookbackDays));
        var max = Math.Clamp(opts.MaxPerRun, 1, 100);

        var candidates = await db.Vulnerabilities
            .Where(v => v.CvssScore == null && !v.IsWithdrawn && v.ModifiedAt >= cutoff
                && (cursor == null || v.PublishedAt < cursor)
                && (v.CanonicalId.StartsWith("CVE-") || v.Aliases.Any(a => a.AliasType == AliasType.Cve)))
            .OrderByDescending(v => v.PublishedAt)
            .Take(max)
            .Select(v => new
            {
                v.PublishedAt,
                CveId = v.CanonicalId.StartsWith("CVE-")
                    ? v.CanonicalId
                    : v.Aliases.Where(a => a.AliasType == AliasType.Cve).Select(a => a.Alias).First(),
            })
            .ToListAsync(ct);

        // Without a key NVD allows 5 requests per 30 seconds; with one, 50.
        var delay = string.IsNullOrWhiteSpace(opts.ApiKey) ? TimeSpan.FromSeconds(6.5) : TimeSpan.FromSeconds(0.7);
        var enriched = 0;
        var reached = 0;
        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (reached++ > 0)
            {
                await Task.Delay(delay, ct);
            }

            NvdResponse? response;
            try
            {
                response = await FetchAsync(candidate.CveId, opts.ApiKey, ct);
            }
            catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            {
                logger.LogInformation("NVD rate limit reached after {Count} lookups; resuming next pass.", reached - 1);
                var resume = candidates.Take(reached - 1).LastOrDefault()?.PublishedAt ?? cursor;
                return await SaveCursorAsync(db, resume, enriched, ct);
            }

            var best = response?.Vulnerabilities?.FirstOrDefault()?.Cve?.Metrics?.Best();
            if (best is { } m && await upserter.ApplyNvdSeverityAsync(candidate.CveId, m.Score, m.Vector, m.Source, ct))
            {
                enriched++;
            }
        }

        // Fewer than a full page means the end of the list: start over from the newest next time.
        DateTimeOffset? next = candidates.Count < max ? null : candidates[^1].PublishedAt;
        logger.LogInformation("NVD enrichment looked up {Looked} CVEs and rated {Enriched}.", candidates.Count, enriched);
        return await SaveCursorAsync(db, next, enriched, ct);
    }

    private async Task<IngestionResult> SaveCursorAsync(
        ThreatwatchDbContext db, DateTimeOffset? cursor, int enriched, CancellationToken ct)
    {
        // The upserter clears the change tracker, so reload the state. The runner only stores
        // non-empty watermarks, so a reset to null has to be written here.
        var state = await IngestionStateHelper.GetOrCreateAsync(db, Source, ct);
        state.Watermark = cursor?.ToString("O");
        await db.SaveChangesAsync(ct);
        return IngestionResult.Success(enriched, null);
    }

    private async Task<NvdResponse?> FetchAsync(string cveId, string? apiKey, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"rest/json/cves/2.0?cveId={Uri.EscapeDataString(cveId)}");
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            request.Headers.Add("apiKey", apiKey);
        }

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        return await JsonSerializer.DeserializeAsync<NvdResponse>(stream, cancellationToken: ct);
    }
}
