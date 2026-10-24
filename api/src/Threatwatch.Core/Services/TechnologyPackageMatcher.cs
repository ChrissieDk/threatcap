using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Services;

public static class TechnologyPackageMatcher
{
    public const int MinFuzzyTokenLength = 4;

    public static bool IsEcosystemWide(Technology technology) =>
        technology.Type == TechnologyType.Ecosystem && technology.Ecosystem is not null;

    public static bool Matches(
        Technology technology,
        Ecosystem ecosystem,
        string packageName,
        string? displayName = null)
    {
        if (IsEcosystemWide(technology))
        {
            return technology.Ecosystem == ecosystem;
        }

        if (technology.Ecosystem is { } scoped && ecosystem != scoped)
        {
            return false;
        }

        var tokens = Names(technology);
        return TokenMatches(tokens, packageName)
            || (displayName is not null && TokenMatches(tokens, displayName));
    }

    public static HashSet<string> Names(Technology technology)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Add(names, technology.Name);
        Add(names, technology.Slug);
        if (technology.Slug.StartsWith("pkg-", StringComparison.OrdinalIgnoreCase))
        {
            Add(names, technology.Slug["pkg-".Length..]);
        }

        foreach (var alias in technology.Aliases)
        {
            Add(names, alias);
        }

        return names;
    }

    public static bool TokenMatches(IReadOnlyCollection<string> tokens, string packageName)
    {
        var value = packageName.Trim();
        if (value.Length == 0 || tokens.Count == 0)
        {
            return false;
        }

        var lastSlash = value.LastIndexOf('/');
        var lastSegment = lastSlash >= 0 ? value[(lastSlash + 1)..] : value;

        foreach (var token in tokens)
        {
            if (value.Equals(token, StringComparison.OrdinalIgnoreCase)
                || lastSegment.Equals(token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (token.Length < MinFuzzyTokenLength)
            {
                continue;
            }

            if (value.StartsWith(token + "-", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith(token + "/", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("@" + token + "/", StringComparison.OrdinalIgnoreCase)
                || value.EndsWith("/" + token, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void Add(HashSet<string> names, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            names.Add(value.Trim());
        }
    }
}
