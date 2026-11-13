using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Scoring;
using Threatwatch.Ingestion.Normalization;

namespace Threatwatch.Ingestion.Providers;

public sealed class OsvRecord
{
    [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
    [JsonPropertyName("summary")] public string? Summary { get; set; }
    [JsonPropertyName("details")] public string? Details { get; set; }
    [JsonPropertyName("aliases")] public List<string>? Aliases { get; set; }
    [JsonPropertyName("related")] public List<string>? Related { get; set; }
    [JsonPropertyName("published")] public string? Published { get; set; }
    [JsonPropertyName("modified")] public string? Modified { get; set; }
    [JsonPropertyName("withdrawn")] public string? Withdrawn { get; set; }
    [JsonPropertyName("severity")] public List<OsvSeverity>? Severity { get; set; }
    [JsonPropertyName("affected")] public List<OsvAffected>? Affected { get; set; }
    [JsonPropertyName("references")] public List<OsvReference>? References { get; set; }
    [JsonPropertyName("database_specific")] public JsonElement? DatabaseSpecific { get; set; }

    public List<string> AllAliases()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (Aliases is not null)
        {
            foreach (var a in Aliases) set.Add(a);
        }

        if (Related is not null)
        {
            foreach (var a in Related) set.Add(a);
        }

        set.Remove(Id);
        return [.. set];
    }

    public DateTimeOffset? PublishedParsed => ParseRfc3339(Published);
    public DateTimeOffset? ModifiedParsed => ParseRfc3339(Modified);
    public DateTimeOffset? WithdrawnParsed => ParseRfc3339(Withdrawn);

    public static DateTimeOffset? ParseRfc3339(string? value)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out var dto) ? dto : null;

    /// <summary>
    /// Best severity for this advisory. A CVSS v3 vector is scored exactly; otherwise the advisory's
    /// own label (GitHub's "severity": LOW/MODERATE/HIGH/CRITICAL) sets the band. A v3 score is preferred
    /// over a v4 one (v3 is the long-established basis for existing bands); a v4-only advisory is scored
    /// from its vector.
    /// </summary>
    public (decimal? Score, string? Vector, Severity Band, string Source)? BestSeverity()
    {
        decimal? v3Score = null;
        string? v3Vector = null;
        decimal? v4Score = null;
        string? v4Vector = null;
        decimal? plainScore = null;

        foreach (var sev in Severity ?? [])
        {
            var vector = sev.Vector;
            if (vector is not null && vector.StartsWith("CVSS:3", StringComparison.OrdinalIgnoreCase))
            {
                var score = CvssCalculator.ScoreV3(vector);
                if (score is { } s && (v3Score is null || s > v3Score)) (v3Score, v3Vector) = (s, vector);
            }
            else if (vector is not null && vector.StartsWith("CVSS:4", StringComparison.OrdinalIgnoreCase))
            {
                var score = CvssV4Calculator.ScoreV4(vector);
                if (score is { } s && (v4Score is null || s > v4Score)) (v4Score, v4Vector) = (s, vector);
                else v4Vector ??= vector;
            }
            else if (sev.ScoreNumber is { } n and >= 0 and <= 10 && (plainScore is null || n > plainScore))
            {
                plainScore = n;
            }
        }

        if (v3Score is { } exact) return (exact, v3Vector, CvssParser.Band(exact), "CVSS_V3");
        if (v4Score is { } v4) return (v4, v4Vector, CvssParser.Band(v4), "CVSS_V4");
        if (plainScore is { } plain) return (plain, null, CvssParser.Band(plain), "CVSS");

        var label = LabelSeverity();
        if (label != Core.Enums.Severity.Unknown) return (null, v4Vector, label, v4Vector is null ? "LABEL" : "CVSS_V4");
        return v4Vector is null ? null : (null, v4Vector, Core.Enums.Severity.Unknown, "CVSS_V4");
    }

    private Severity LabelSeverity()
    {
        if (DatabaseSpecific is { ValueKind: JsonValueKind.Object } db
            && db.TryGetProperty("severity", out var el) && el.ValueKind == JsonValueKind.String)
        {
            return el.GetString()?.Trim().ToUpperInvariant() switch
            {
                "CRITICAL" => Core.Enums.Severity.Critical,
                "HIGH" => Core.Enums.Severity.High,
                "MODERATE" or "MEDIUM" => Core.Enums.Severity.Medium,
                "LOW" => Core.Enums.Severity.Low,
                _ => Core.Enums.Severity.Unknown,
            };
        }

        return Core.Enums.Severity.Unknown;
    }
}

public sealed class OsvSeverity
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("score")] public string? Score { get; set; }

    /// <summary>CVSS vector string (e.g. "CVSS:3.1/AV:N/..."), when score is a vector.</summary>
    public string? Vector => Score?.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase) == true ? Score : null;

    /// <summary>Numeric score when the score field is a plain number.</summary>
    public decimal? ScoreNumber =>
        Score is not null && !Score.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase)
        && decimal.TryParse(Score, NumberStyles.Number, CultureInfo.InvariantCulture, out var v) ? v : null;
}

public sealed class OsvAffected
{
    [JsonPropertyName("package")] public OsvPackage? Package { get; set; }
    [JsonPropertyName("ranges")] public List<OsvRange>? Ranges { get; set; }
    [JsonPropertyName("versions")] public List<string>? Versions { get; set; }

    public string[] FixedVersions()
    {
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var range in Ranges ?? [])
        {
            foreach (var ev in range.Events ?? [])
            {
                if (string.Equals(ev.Event, "fixed", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(ev.Value))
                {
                    set.Add(ev.Value!);
                }
            }
        }

        return [.. set];
    }
}

public sealed class OsvPackage
{
    [JsonPropertyName("ecosystem")] public string? Ecosystem { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("purl")] public string? Purl { get; set; }
}

public sealed class OsvRange
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("repo")] public string? Repo { get; set; }
    [JsonPropertyName("events")] public List<OsvRangeEvent>? Events { get; set; }
}

public sealed class OsvRangeEvent
{
    [JsonPropertyName("introduced")] public string? Introduced { get; set; }
    [JsonPropertyName("fixed")] public string? Fixed { get; set; }
    [JsonPropertyName("last_affected")] public string? LastAffected { get; set; }
    [JsonPropertyName("limit")] public string? Limit { get; set; }

    public string? Event => Introduced is not null ? "introduced"
        : Fixed is not null ? "fixed"
        : LastAffected is not null ? "last_affected"
        : Limit is not null ? "limit" : null;

    public string? Value => Introduced ?? Fixed ?? LastAffected ?? Limit;
}

public sealed class OsvReference
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
}

public sealed class OsvQueryRequest
{
    [JsonPropertyName("modified_since")] public string? ModifiedSince { get; set; }
}

public sealed class OsvVulnerabilityListResponse
{
    [JsonPropertyName("vulns")] public List<OsvVulnerabilityId>? Vulns { get; set; }
    [JsonPropertyName("next_page_token")] public string? NextPageToken { get; set; }
}

public sealed class OsvVulnerabilityId
{
    [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
    [JsonPropertyName("modified")] public string? Modified { get; set; }
}
