using System.Numerics;
using System.Text.RegularExpressions;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Projects;

/// <summary>
/// Orders version strings per ecosystem. npm, Cargo, Go and NuGet follow semver (NuGet with a
/// fourth numeric part); PyPI follows a simplified PEP 440; Maven is approximated by treating
/// unknown qualifiers as pre-releases. Unparseable versions compare as equal to nothing
/// (<see cref="TryParse"/> returns false) so callers can report "could not check".
/// </summary>
public static partial class VersionComparer
{
    public static bool TryParse(Ecosystem ecosystem, string? raw, out ParsedVersion version)
    {
        version = default!;
        if (string.IsNullOrWhiteSpace(raw)) return false;

        var parsed = ecosystem == Ecosystem.PyPI ? ParsePep440(raw) : ParseSemverLike(raw, ecosystem);
        if (parsed is null) return false;
        version = parsed;
        return true;
    }

    public static int Compare(Ecosystem ecosystem, string a, string b)
    {
        if (!TryParse(ecosystem, a, out var pa) || !TryParse(ecosystem, b, out var pb))
        {
            return string.CompareOrdinal(a, b);
        }

        return pa.CompareTo(pb);
    }

    private static ParsedVersion? ParseSemverLike(string raw, Ecosystem ecosystem)
    {
        var text = raw.Trim().TrimStart('v', 'V', '=');
        if (ecosystem == Ecosystem.Maven)
        {
            // Spring-style "5.3.30.RELEASE" / "1.0.Final" are plain releases.
            text = Regex.Replace(text, @"[.-](release|final|ga)$", "", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
        }

        var plus = text.IndexOf('+');
        if (plus >= 0) text = text[..plus]; // build metadata never affects precedence

        var dash = text.IndexOf('-');
        var core = dash >= 0 ? text[..dash] : text;
        var pre = dash >= 0 ? text[(dash + 1)..] : null;

        var parts = core.Split('.');
        if (parts.Length == 0 || parts.Length > 6) return null;
        var release = new List<BigInteger>();
        foreach (var part in parts)
        {
            if (!BigInteger.TryParse(part, out var n) || n < 0) return null;
            release.Add(n);
        }

        // Maven-style release qualifiers are not pre-releases.
        if (pre is not null && ecosystem == Ecosystem.Maven
            && ReleaseQualifiers.Contains(pre.ToLowerInvariant()))
        {
            pre = null;
        }

        var preIds = pre is null ? [] : pre.Split('.').Select(PreId.From).ToArray();
        return new ParsedVersion(0, release, preKind: pre is null ? 3 : 0, preIds, 0, null);
    }

    private static readonly HashSet<string> ReleaseQualifiers = ["release", "final", "ga", ""];

    private static ParsedVersion? ParsePep440(string raw)
    {
        var m = Pep440().Match(raw.Trim());
        if (!m.Success) return null;

        var epoch = m.Groups["epoch"].Success ? int.Parse(m.Groups["epoch"].Value) : 0;
        var release = m.Groups["release"].Value.Split('.').Select(BigInteger.Parse).ToList();

        // Ordering: dev < a < b < rc < final < post. A pure dev release sorts below pre-releases.
        var preKind = 3;
        var preNum = 0;
        if (m.Groups["pre"].Success)
        {
            preKind = m.Groups["pre"].Value.ToLowerInvariant() switch
            {
                "a" or "alpha" => 0,
                "b" or "beta" => 1,
                _ => 2, // rc, c, pre, preview
            };
            preNum = m.Groups["prenum"].Success && m.Groups["prenum"].Value.Length > 0
                ? int.Parse(m.Groups["prenum"].Value) : 0;
        }

        var post = 0;
        if (m.Groups["post"].Success)
        {
            post = (m.Groups["postnum2"].Value.Length > 0 ? int.Parse(m.Groups["postnum2"].Value) : 0) + 1;
        }
        else if (m.Groups["postnum"].Success)
        {
            post = int.Parse(m.Groups["postnum"].Value) + 1;
        }

        int? dev = m.Groups["dev"].Success
            ? (m.Groups["devnum"].Success && m.Groups["devnum"].Value.Length > 0 ? int.Parse(m.Groups["devnum"].Value) : 0)
            : null;

        return new ParsedVersion(epoch, release, preKind, [PreId.OfNumber(preNum)], post, dev);
    }

    [GeneratedRegex(
        @"^v?(?:(?<epoch>\d+)!)?(?<release>\d+(?:\.\d+)*)(?:[-_.]?(?<pre>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?<prenum>\d*))?(?:(?:-(?<postnum>\d+))|(?:[-_.]?(?<post>post|rev|r)[-_.]?(?<postnum2>\d*)))?(?:[-_.]?(?<dev>dev)[-_.]?(?<devnum>\d*))?(?:\+[a-z0-9.\-_]+)?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex Pep440();
}

public readonly record struct PreId(bool IsNumeric, BigInteger Number, string Text)
{
    public static PreId From(string id) =>
        BigInteger.TryParse(id, out var n) ? new PreId(true, n, id) : new PreId(false, 0, id);

    public static PreId OfNumber(int n) => new(true, n, n.ToString());
}

public sealed class ParsedVersion : IComparable<ParsedVersion>
{
    private readonly int _epoch;
    private readonly IReadOnlyList<BigInteger> _release;
    private readonly int _preKind; // lower sorts first; 3 = final release
    private readonly IReadOnlyList<PreId> _pre;
    private readonly int _post;
    private readonly int? _dev;

    public ParsedVersion(int epoch, IReadOnlyList<BigInteger> release, int preKind, IReadOnlyList<PreId> pre, int post, int? dev)
    {
        _epoch = epoch;
        _release = release;
        _preKind = preKind;
        _pre = pre;
        _post = post;
        _dev = dev;
    }

    public int CompareTo(ParsedVersion? other)
    {
        if (other is null) return 1;
        var c = _epoch.CompareTo(other._epoch);
        if (c != 0) return c;

        var len = Math.Max(_release.Count, other._release.Count);
        for (var i = 0; i < len; i++)
        {
            var a = i < _release.Count ? _release[i] : BigInteger.Zero;
            var b = i < other._release.Count ? other._release[i] : BigInteger.Zero;
            c = a.CompareTo(b);
            if (c != 0) return c;
        }

        // A dev-only release (1.0.dev1) sorts before 1.0a1.
        var aKind = _dev is not null && _preKind == 3 && _post == 0 ? -1 : _preKind;
        var bKind = other._dev is not null && other._preKind == 3 && other._post == 0 ? -1 : other._preKind;
        c = aKind.CompareTo(bKind);
        if (c != 0) return c;

        if (_preKind != 3 || other._preKind != 3)
        {
            c = ComparePre(_pre, other._pre);
            if (c != 0) return c;
        }

        c = _post.CompareTo(other._post);
        if (c != 0) return c;

        if (_dev is null && other._dev is null) return 0;
        if (_dev is null) return 1;
        if (other._dev is null) return -1;
        return _dev.Value.CompareTo(other._dev.Value);
    }

    private static int ComparePre(IReadOnlyList<PreId> a, IReadOnlyList<PreId> b)
    {
        var len = Math.Min(a.Count, b.Count);
        for (var i = 0; i < len; i++)
        {
            int c;
            if (a[i].IsNumeric && b[i].IsNumeric) c = a[i].Number.CompareTo(b[i].Number);
            else if (a[i].IsNumeric) c = -1; // numeric identifiers sort below alphanumeric
            else if (b[i].IsNumeric) c = 1;
            else c = string.CompareOrdinal(a[i].Text, b[i].Text);
            if (c != 0) return c;
        }

        return a.Count.CompareTo(b.Count);
    }
}
