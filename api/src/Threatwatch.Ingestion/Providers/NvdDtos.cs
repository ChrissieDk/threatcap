using System.Text.Json.Serialization;

namespace Threatwatch.Ingestion.Providers;

public sealed class NvdResponse
{
    [JsonPropertyName("vulnerabilities")] public List<NvdVulnerability>? Vulnerabilities { get; set; }
}

public sealed class NvdVulnerability
{
    [JsonPropertyName("cve")] public NvdCve? Cve { get; set; }
}

public sealed class NvdCve
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("metrics")] public NvdMetrics? Metrics { get; set; }
}

public sealed class NvdMetrics
{
    [JsonPropertyName("cvssMetricV40")] public List<NvdMetric>? V40 { get; set; }
    [JsonPropertyName("cvssMetricV31")] public List<NvdMetric>? V31 { get; set; }
    [JsonPropertyName("cvssMetricV30")] public List<NvdMetric>? V30 { get; set; }

    /// <summary>
    /// Best CVSS metric NVD publishes: v3.1, then v3.0, then v4.0 (v3 first for consistency with
    /// <see cref="OsvRecord.BestSeverity"/>), preferring NVD's own ("Primary") analysis.
    /// </summary>
    public (decimal Score, string Vector, string Source)? Best()
    {
        foreach (var (list, source) in new[] { (V31, "CVSS_V3"), (V30, "CVSS_V3"), (V40, "CVSS_V4") })
        {
            var metric = list?.OrderByDescending(m => string.Equals(m.Type, "Primary", StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault(m => m.CvssData is { BaseScore: not null, VectorString: not null });
            if (metric?.CvssData is { BaseScore: { } score, VectorString: { } vector })
            {
                return (score, vector, source);
            }
        }

        return null;
    }
}

public sealed class NvdMetric
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("cvssData")] public NvdCvssData? CvssData { get; set; }
}

public sealed class NvdCvssData
{
    [JsonPropertyName("vectorString")] public string? VectorString { get; set; }
    [JsonPropertyName("baseScore")] public decimal? BaseScore { get; set; }
}
