using System.Globalization;
using System.Text.Json.Serialization;
using Threatwatch.Core.Enums;
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

    /// <summary>Pick the severity entry with the highest base score; derive the band.</summary>
    public (decimal Score, string? Vector, Severity Band, string Source)? BestSeverity()
    {
        (decimal, string?, Severity, string)? best = null;
        foreach (var sev in Severity ?? [])
        {
            decimal? score = sev.ScoreNumber ?? CvssParser.ExtractScore(sev.Score ?? sev.Vector);
            if (!score.HasValue)
            {
                continue;
            }

            var band = CvssParser.Band(score.Value);
            var source = sev.Type ?? "CVSS";
            if (best is null || score.Value > best.Value.Item1)
            {
                best = (score.Value, sev.Vector ?? sev.Score, band, source);
            }
        }

        return best;
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
