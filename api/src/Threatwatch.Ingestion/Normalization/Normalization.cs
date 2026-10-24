using System.Globalization;
using System.Text.Json;
using Threatwatch.Core.Enums;

namespace Threatwatch.Ingestion.Normalization;

public static class CvssParser
{
    /// <summary>
    /// Parse the base score out of a CVSS vector string ("CVSS:3.1/AV:N/..."), which
    /// does not contain the score. The caller supplies the score if the source
    /// provides it separately; this only validates and derives the severity band.
    /// </summary>
    public static Severity Band(decimal score) => score switch
    {
        >= 9.0m => Severity.Critical,
        >= 7.0m => Severity.High,
        >= 4.0m => Severity.Medium,
        > 0.0m => Severity.Low,
        _ => Severity.Unknown,
    };

    /// <summary>
    /// Extract a base score embedded in free text, e.g. a score prefix on a vector,
    /// "9.8" alone, or a vector with a leading score. Returns null when absent.
    /// </summary>
    public static decimal? ExtractScore(string? scoreOrVector)
    {
        if (string.IsNullOrWhiteSpace(scoreOrVector))
        {
            return null;
        }

        var s = scoreOrVector.Trim();
        // Match the first numeric token that looks like a CVSS score (0-10).
        var i = 0;
        while (i < s.Length)
        {
            if (char.IsDigit(s[i]) || (s[i] == '.' && i + 1 < s.Length && char.IsDigit(s[i + 1])))
            {
                var j = i;
                while (j < s.Length && (char.IsDigit(s[j]) || s[j] == '.'))
                {
                    j++;
                }

                if (decimal.TryParse(s[i..j], NumberStyles.Number, CultureInfo.InvariantCulture, out var value) && value is >= 0m and <= 10m)
                {
                    return value;
                }

                i = j;
            }
            else
            {
                i++;
            }
        }

        return null;
    }
}

public static class PackageNameNormalizer
{
    /// <summary>Normalize an ecosystem package name for matching: lowercase, trimmed.</summary>
    public static string Normalize(string packageName)
    {
        ArgumentNullException.ThrowIfNull(packageName);
        return packageName.Trim().ToLowerInvariant();
    }

    /// <summary>Map an OSV ecosystem string onto our enum. Case-insensitive.</summary>
    public static Ecosystem MapEcosystem(string? osvEcosystem) => (osvEcosystem ?? string.Empty).ToLowerInvariant() switch
    {
        "npm" => Ecosystem.Npm,
        "nuget" => Ecosystem.NuGet,
        "pypi" => Ecosystem.PyPI,
        "maven" => Ecosystem.Maven,
        "crates.io" => Ecosystem.Cargo,
        "go" => Ecosystem.Go,
        "github actions" => Ecosystem.GithubActions,
        "debian" or "ubuntu" or "alpine" or "rocky linux" or "red hat" or "linux" => Ecosystem.Linux,
        _ => Ecosystem.Other,
    };
}

public static class CanonicalIdSelector
{
    /// <summary>
    /// Choose a canonical id for a vulnerability given all known aliases.
    /// Prefers the first CVE alias, then the first GHSA alias, then any other alias,
    /// then falls back to the record's own id.
    /// </summary>
    public static string Select(string recordId, IEnumerable<string> aliases)
    {
        var all = new[] { recordId }.Concat(aliases.Where(a => !string.IsNullOrWhiteSpace(a)));

        return all.FirstOrDefault(IsCve)
            ?? all.FirstOrDefault(IsGhsa)
            ?? all.FirstOrDefault(a => a != recordId)
            ?? recordId;
    }

    public static bool IsCve(string alias) => alias.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase);
    public static bool IsGhsa(string alias) => alias.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase);

    public static AliasType Classify(string alias)
    {
        if (IsCve(alias)) return AliasType.Cve;
        if (IsGhsa(alias)) return AliasType.Ghsa;
        return AliasType.Other;
    }
}

public static class OsvJsonReader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}
