using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Normalization;

namespace Threatwatch.Ingestion.Providers;

public sealed class CisaKevFeed
{
    [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;
    [JsonPropertyName("catalogVersion")] public string? CatalogVersion { get; set; }
    [JsonPropertyName("dateReleased")] public string? DateReleased { get; set; }
    [JsonPropertyName("count")] public int Count { get; set; }
    [JsonPropertyName("vulnerabilities")] public List<CisaKevEntry> Vulnerabilities { get; set; } = [];
}

public sealed class CisaKevEntry
{
    [JsonPropertyName("cveID")] public string CveId { get; set; } = string.Empty;
    [JsonPropertyName("vendorProject")] public string VendorProject { get; set; } = string.Empty;
    [JsonPropertyName("product")] public string Product { get; set; } = string.Empty;
    [JsonPropertyName("vulnerabilityName")] public string VulnerabilityName { get; set; } = string.Empty;
    [JsonPropertyName("dateAdded")] public string DateAdded { get; set; } = string.Empty;
    [JsonPropertyName("shortDescription")] public string ShortDescription { get; set; } = string.Empty;
    [JsonPropertyName("requiredAction")] public string RequiredAction { get; set; } = string.Empty;
    [JsonPropertyName("dueDate")] public string DueDate { get; set; } = string.Empty;
    [JsonPropertyName("knownRansomwareCampaignUse")] public string? KnownRansomwareCampaignUse { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

public class CisaKevDataSource(
    HttpClient httpClient,
    ILogger<CisaKevDataSource> logger) : ISecurityDataSource
{
    private const string FeedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private const string CatalogUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

    public string Name => "cisa-kev";
    public IngestionSource Source => IngestionSource.CisaKev;
    public TimeSpan Interval => TimeSpan.FromHours(6);

    public async Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct)
    {
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var upserter = scope.ServiceProvider.GetRequiredService<VulnerabilityUpserter>();

        var feed = OsvJsonReader.Deserialize<CisaKevFeed>(
            await httpClient.GetStringAsync(FeedUrl, ct));

        if (feed is null)
        {
            return IngestionResult.Failure("Failed to deserialize KEV feed.");
        }

        DateTimeOffset? maxDateAdded = null;
        var processed = 0;

        foreach (var entry in feed.Vulnerabilities)
        {
            ct.ThrowIfCancellationRequested();

            if (!DateTimeOffset.TryParse(entry.DateAdded, out var dateAdded))
            {
                dateAdded = DateTimeOffset.UtcNow;
            }

            maxDateAdded = maxDateAdded.HasValue && maxDateAdded.Value > dateAdded ? maxDateAdded : dateAdded;

            await upserter.UpsertKnownExploitedAsync(
                cveId: entry.CveId,
                title: entry.VulnerabilityName,
                description: entry.ShortDescription,
                exploitedSince: dateAdded,
                sourceUrl: CatalogUrl,
                ct: ct);

            processed++;
        }

        logger.LogInformation("KEV sync processed {Count} entries (watermark {Watermark}).",
            processed, maxDateAdded);
        return IngestionResult.Success(processed, maxDateAdded?.ToString("O"));
    }
}
