using System.Text.Json;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Projects;

public enum RangeVerdict
{
    /// <summary>The ranges cannot be evaluated for this version (no usable ranges, unparseable version).</summary>
    Unknown,
    NotAffected,
    Affected,
}

public sealed record RangeResult(RangeVerdict Verdict, string? FixedIn);

/// <summary>
/// Evaluates stored OSV ranges (<c>AffectedPackage.AffectedRanges</c>) for one version, following
/// the OSV schema's algorithm: events are ordered by version and replayed, with
/// <c>introduced</c> switching "affected" on and <c>fixed</c>/<c>last_affected</c> switching it off.
/// Only SEMVER and ECOSYSTEM ranges are evaluated; GIT ranges (commit hashes) cannot be.
/// </summary>
public static class OsvRangeEvaluator
{
    public static RangeResult Evaluate(Ecosystem ecosystem, string rangesJson, string? version)
    {
        if (!VersionComparer.TryParse(ecosystem, version, out var target))
        {
            return new RangeResult(RangeVerdict.Unknown, null);
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(rangesJson);
        }
        catch (JsonException)
        {
            return new RangeResult(RangeVerdict.Unknown, null);
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return new RangeResult(RangeVerdict.Unknown, null);
            }

            var evaluated = false;
            foreach (var range in doc.RootElement.EnumerateArray())
            {
                var type = range.TryGetProperty("type", out var t) ? t.GetString() : null;
                if (!string.Equals(type, "SEMVER", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(type, "ECOSYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!range.TryGetProperty("events", out var eventsEl) || eventsEl.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                var events = ReadEvents(ecosystem, eventsEl);
                if (events.Count == 0) continue;

                evaluated = true;
                var result = EvaluateRange(ecosystem, events, target);
                if (result.Verdict == RangeVerdict.Affected) return result;
            }

            return new RangeResult(evaluated ? RangeVerdict.NotAffected : RangeVerdict.Unknown, null);
        }
    }

    private sealed record Ev(string Kind, string Value, ParsedVersion Parsed);

    private static List<Ev> ReadEvents(Ecosystem ecosystem, JsonElement eventsEl)
    {
        var list = new List<Ev>();
        foreach (var e in eventsEl.EnumerateArray())
        {
            foreach (var kind in new[] { "introduced", "fixed", "last_affected" })
            {
                if (!e.TryGetProperty(kind, out var v) || v.ValueKind != JsonValueKind.String) continue;
                var value = v.GetString()!;
                var parsed = value == "0"
                    ? new ParsedVersion(0, [0], 3, [], 0, null)
                    : VersionComparer.TryParse(ecosystem, value, out var p) ? p : null;
                if (parsed is not null) list.Add(new Ev(kind, value, parsed));
            }
        }

        // Replay in version order; at equal versions "introduced" goes first.
        return list
            .OrderBy(x => x.Parsed)
            .ThenBy(x => x.Kind == "introduced" ? 0 : 1)
            .ToList();
    }

    private static RangeResult EvaluateRange(Ecosystem ecosystem, List<Ev> events, ParsedVersion target)
    {
        var affected = false;
        foreach (var ev in events)
        {
            switch (ev.Kind)
            {
                case "introduced" when target.CompareTo(ev.Parsed) >= 0:
                    affected = true;
                    break;
                case "fixed" when target.CompareTo(ev.Parsed) >= 0:
                    affected = false;
                    break;
                case "last_affected" when target.CompareTo(ev.Parsed) > 0:
                    affected = false;
                    break;
            }
        }

        if (!affected) return new RangeResult(RangeVerdict.NotAffected, null);

        var fix = events.FirstOrDefault(e => e.Kind == "fixed" && target.CompareTo(e.Parsed) < 0);
        return new RangeResult(RangeVerdict.Affected, fix?.Value);
    }
}
