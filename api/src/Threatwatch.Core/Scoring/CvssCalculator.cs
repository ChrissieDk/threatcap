using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Scoring;

/// <summary>
/// Computes the CVSS v3.x base score from a vector string, per the FIRST specification.
/// Vector strings carry the metrics, not the score, so the score has to be calculated.
/// CVSS v4.0 uses a lookup-table algorithm and is not computed here.
/// </summary>
public static class CvssCalculator
{
    public static decimal? ScoreV3(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector)
            || !(vector.StartsWith("CVSS:3.1/", StringComparison.OrdinalIgnoreCase)
                || vector.StartsWith("CVSS:3.0/", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in vector.Split('/').Skip(1))
        {
            var kv = part.Split(':');
            if (kv.Length == 2) m[kv[0]] = kv[1].ToUpperInvariant();
        }

        if (!m.TryGetValue("S", out var scopeRaw) || scopeRaw is not ("U" or "C")) return null;
        var changed = scopeRaw == "C";

        double? av = Pick(m, "AV", ("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2));
        double? ac = Pick(m, "AC", ("L", 0.77), ("H", 0.44));
        double? pr = Pick(m, "PR", ("N", 0.85), ("L", changed ? 0.68 : 0.62), ("H", changed ? 0.5 : 0.27));
        double? ui = Pick(m, "UI", ("N", 0.85), ("R", 0.62));
        double? c = Pick(m, "C", ("H", 0.56), ("L", 0.22), ("N", 0));
        double? i = Pick(m, "I", ("H", 0.56), ("L", 0.22), ("N", 0));
        double? a = Pick(m, "A", ("H", 0.56), ("L", 0.22), ("N", 0));
        if (av is null || ac is null || pr is null || ui is null || c is null || i is null || a is null) return null;

        var iss = 1 - (1 - c.Value) * (1 - i.Value) * (1 - a.Value);
        var impact = changed
            ? 7.52 * (iss - 0.029) - 3.25 * Math.Pow(iss - 0.02, 15)
            : 6.42 * iss;
        if (impact <= 0) return 0m;

        var exploitability = 8.22 * av.Value * ac.Value * pr.Value * ui.Value;
        var raw = changed ? Math.Min(1.08 * (impact + exploitability), 10) : Math.Min(impact + exploitability, 10);
        return (decimal)RoundUp(raw);
    }

    private static double? Pick(Dictionary<string, string> metrics, string key, params (string Value, double Weight)[] options)
    {
        if (!metrics.TryGetValue(key, out var value)) return null;
        foreach (var (v, w) in options)
        {
            if (v == value) return w;
        }

        return null;
    }

    /// <summary>The CVSS 3.1 "Roundup" function (avoids floating point surprises).</summary>
    private static double RoundUp(double input)
    {
        var intInput = (long)Math.Round(input * 100000);
        return intInput % 10000 == 0 ? intInput / 100000.0 : (Math.Floor(intInput / 10000.0) + 1) / 10.0;
    }
}

public static class PriorityScoring
{
    /// <summary>Representative score for advisories that only carry a severity label.</summary>
    public static decimal? Midpoint(Severity severity) => severity switch
    {
        Severity.Critical => 9.5m,
        Severity.High => 8.0m,
        Severity.Medium => 5.5m,
        Severity.Low => 2.5m,
        _ => null,
    };

    /// <summary>
    /// Priority = base score x (1 + EPSS) x 2 if exploited. Falls back to the severity label,
    /// and treats an actively exploited advisory with no rating at all as 7.0 so it still ranks.
    /// </summary>
    public static double? Compute(decimal? cvssScore, Severity severity, double? epss, bool isKnownExploited)
    {
        var basis = cvssScore ?? Midpoint(severity) ?? (isKnownExploited ? 7.0m : null);
        return basis is { } b ? (double)b * (1 + (epss ?? 0)) * (isKnownExploited ? 2 : 1) : null;
    }
}
