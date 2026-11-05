using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Projects;

public enum VersionKind
{
    /// <summary>The exact installed/resolved version.</summary>
    Exact = 0,

    /// <summary>The lower bound of a declared range (e.g. <c>^4.17.0</c>); the real version may be newer.</summary>
    Declared = 1,
}

public sealed record ParsedDependency(
    Ecosystem Ecosystem,
    string Name,
    string DisplayName,
    string? Version,
    VersionKind Kind,
    bool IsDev,
    bool IsDirect);

public sealed record ParseResult(IReadOnlyList<ParsedDependency> Dependencies, IReadOnlyList<string> Warnings);

public static class PackageNames
{
    public static string Normalize(Ecosystem ecosystem, string name)
    {
        var value = name.Trim().ToLowerInvariant();
        return ecosystem == Ecosystem.PyPI ? Regex.Replace(value, "[-_.]+", "-", RegexOptions.None, TimeSpan.FromMilliseconds(100)) : value;
    }
}

/// <summary>
/// Reads dependency manifests, lockfiles and SBOMs into a flat dependency list. Input is
/// untrusted: XML is parsed with DTDs prohibited, JSON depth is bounded, and every parser
/// returns what it could read plus warnings instead of throwing.
/// </summary>
public static class DependencyFileParser
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
    private static readonly JsonDocumentOptions JsonOptions = new() { MaxDepth = 64, CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public static readonly string[] SupportedFiles =
    [
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
        "poetry.lock", "uv.lock", "Pipfile.lock",
        "*.csproj", "Directory.Packages.props", "packages.config", "go.mod", "Cargo.toml", "Cargo.lock",
        "pom.xml", "CycloneDX / SPDX JSON SBOM",
    ];

    public static ParseResult Parse(string fileName, string content)
    {
        var warnings = new List<string>();
        var deps = new List<ParsedDependency>();
        var name = Path.GetFileName(fileName.Replace('\\', '/')).ToLowerInvariant();

        try
        {
            switch (name)
            {
                case "package.json": PackageJson(content, deps, warnings); break;
                case "package-lock.json" or "npm-shrinkwrap.json": PackageLock(content, deps); break;
                case "yarn.lock": YarnLock(content, deps); break;
                case "pnpm-lock.yaml": PnpmLock(content, deps); break;
                case "go.mod": GoMod(content, deps); break;
                case "poetry.lock" or "uv.lock": PythonTomlLock(content, deps); break;
                case "pipfile.lock": PipfileLock(content, deps); break;
                case "cargo.lock": CargoLock(content, deps); break;
                case "cargo.toml": CargoToml(content, deps); break;
                case "pom.xml": Pom(content, deps); break;
                case "packages.config": NuGetXml(content, deps); break;
                default:
                    if (name.StartsWith("requirements") && name.EndsWith(".txt"))
                    {
                        Requirements(content, deps, isDev: name.Contains("dev") || name.Contains("test"));
                    }
                    else if (name.EndsWith(".csproj") || name.EndsWith(".fsproj") || name.EndsWith(".vbproj")
                        || name.EndsWith(".props") || name.EndsWith(".targets"))
                    {
                        NuGetXml(content, deps);
                    }
                    else if (name.EndsWith(".json"))
                    {
                        Sbom(content, deps, warnings, fileName);
                    }
                    else
                    {
                        warnings.Add($"{fileName}: unsupported file type.");
                    }

                    break;
            }
        }
        catch (Exception ex) when (ex is JsonException or XmlException or FormatException or RegexMatchTimeoutException or InvalidOperationException)
        {
            warnings.Add($"{fileName}: could not be read (invalid or unexpected format).");
        }

        if (deps.Count == 0 && warnings.Count == 0)
        {
            warnings.Add($"{fileName}: no dependencies found.");
        }

        return new ParseResult(deps, warnings);
    }

    // ---------------------------------------------------------------- npm

    private static readonly Regex NpmVersion = new(@"^\d+(?:\.(?:\d+|[xX*]))*(?:-[0-9A-Za-z.\-]+)?$", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Lower bound of an npm range, or null when it cannot be expressed as a version.</summary>
    public static (string? Version, VersionKind Kind) ResolveNpmSpec(string? spec)
    {
        if (string.IsNullOrWhiteSpace(spec)) return (null, VersionKind.Declared);
        var s = spec.Trim();
        if (s is "*" or "latest" or "x" or "next" || s.Contains("://") || s.Contains('/')
            || s.StartsWith("git") || s.StartsWith("file:") || s.StartsWith("link:") || s.StartsWith("workspace:")
            || s.StartsWith("npm:") || s.StartsWith("github:"))
        {
            return (null, VersionKind.Declared);
        }

        var first = s.Split("||")[0].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        if (first.StartsWith('<')) return (null, VersionKind.Declared);

        var token = first.TrimStart('^', '~', '>', '=', 'v', 'V');
        if (!NpmVersion.IsMatch(token)) return (null, VersionKind.Declared);

        var hadWildcard = Regex.IsMatch(token, "[xX*]", RegexOptions.None, RegexTimeout);
        token = Regex.Replace(token, @"\.[xX*]", ".0", RegexOptions.None, RegexTimeout);
        var exact = !hadWildcard && token == s;
        return (token, exact ? VersionKind.Exact : VersionKind.Declared);
    }

    private static void PackageJson(string content, List<ParsedDependency> deps, List<string> warnings)
    {
        using var doc = JsonDocument.Parse(content, JsonOptions);
        foreach (var (section, dev) in new[] { ("dependencies", false), ("optionalDependencies", false), ("devDependencies", true) })
        {
            if (!doc.RootElement.TryGetProperty(section, out var el) || el.ValueKind != JsonValueKind.Object) continue;
            foreach (var p in el.EnumerateObject())
            {
                var (version, kind) = ResolveNpmSpec(p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null);
                deps.Add(new ParsedDependency(Ecosystem.Npm, PackageNames.Normalize(Ecosystem.Npm, p.Name), p.Name, version, kind, dev, true));
            }
        }

        if (deps.Count == 0) warnings.Add("package.json: no dependencies declared.");
    }

    private static void PackageLock(string content, List<ParsedDependency> deps)
    {
        using var doc = JsonDocument.Parse(content, JsonOptions);
        var root = doc.RootElement;
        if (root.TryGetProperty("packages", out var packages) && packages.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in packages.EnumerateObject())
            {
                if (p.Name.Length == 0 || p.Value.ValueKind != JsonValueKind.Object) continue;
                if (p.Value.TryGetProperty("link", out var link) && link.ValueKind == JsonValueKind.True) continue;

                var marker = "node_modules/";
                var idx = p.Name.LastIndexOf(marker, StringComparison.Ordinal);
                var name = p.Value.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String
                    ? n.GetString()!
                    : idx >= 0 ? p.Name[(idx + marker.Length)..] : p.Name;
                var version = p.Value.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                var dev = (p.Value.TryGetProperty("dev", out var d) && d.ValueKind == JsonValueKind.True)
                    || (p.Value.TryGetProperty("devOptional", out var d2) && d2.ValueKind == JsonValueKind.True);
                if (version is null) continue;
                deps.Add(new ParsedDependency(Ecosystem.Npm, PackageNames.Normalize(Ecosystem.Npm, name), name, version, VersionKind.Exact, dev, false));
            }
        }
        else if (root.TryGetProperty("dependencies", out var legacy) && legacy.ValueKind == JsonValueKind.Object)
        {
            LegacyLock(legacy, deps, 0);
        }
    }

    private static void LegacyLock(JsonElement deps, List<ParsedDependency> output, int depth)
    {
        if (depth > 40) return;
        foreach (var p in deps.EnumerateObject())
        {
            if (p.Value.ValueKind != JsonValueKind.Object) continue;
            if (p.Value.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String)
            {
                var dev = p.Value.TryGetProperty("dev", out var d) && d.ValueKind == JsonValueKind.True;
                output.Add(new ParsedDependency(Ecosystem.Npm, PackageNames.Normalize(Ecosystem.Npm, p.Name), p.Name, v.GetString(), VersionKind.Exact, dev, false));
            }

            if (p.Value.TryGetProperty("dependencies", out var nested) && nested.ValueKind == JsonValueKind.Object)
            {
                LegacyLock(nested, output, depth + 1);
            }
        }
    }

    private static void YarnLock(string content, List<ParsedDependency> deps)
    {
        List<string> names = [];
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith('#')) continue;

            if (!char.IsWhiteSpace(line[0]) && line.EndsWith(':'))
            {
                names = [];
                foreach (var part in line.TrimEnd(':').Split(','))
                {
                    var spec = part.Trim().Trim('"');
                    var at = spec.LastIndexOf('@');
                    if (at > 0 && !spec.Contains("@workspace:")) names.Add(spec[..at]);
                }

                continue;
            }

            var m = Regex.Match(line, @"^\s+version:?\s+""?([^""\s]+)""?\s*$", RegexOptions.None, RegexTimeout);
            if (m.Success && names.Count > 0)
            {
                foreach (var n in names.Distinct())
                {
                    deps.Add(new ParsedDependency(Ecosystem.Npm, PackageNames.Normalize(Ecosystem.Npm, n), n, m.Groups[1].Value, VersionKind.Exact, false, false));
                }

                names = [];
            }
        }
    }

    private static void PnpmLock(string content, List<ParsedDependency> deps)
    {
        var inPackages = false;
        var current = new Regex(@"^  '?/?((?:@[^/@\s']+/)?[^@\s'/]+)@(\d[^'\s:(]*)", RegexOptions.Compiled, RegexTimeout);
        var legacy = new Regex(@"^  '?/((?:@[^/\s']+/)?[^/\s']+)/(\d[^'\s:(_]*)", RegexOptions.Compiled, RegexTimeout);
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                inPackages = line.StartsWith("packages:");
                continue;
            }

            if (!inPackages) continue;
            var m = current.Match(line);
            if (!m.Success) m = legacy.Match(line);
            if (!m.Success) continue;

            var name = m.Groups[1].Value;
            deps.Add(new ParsedDependency(Ecosystem.Npm, PackageNames.Normalize(Ecosystem.Npm, name), name, m.Groups[2].Value, VersionKind.Exact, false, false));
        }
    }

    // ---------------------------------------------------------------- PyPI

    private static void Requirements(string content, List<ParsedDependency> deps, bool isDev)
    {
        var line = new Regex(@"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(===|==|~=|>=|<=|!=|>|<)\s*([A-Za-z0-9.!+*_-]+))?", RegexOptions.Compiled, RegexTimeout);
        foreach (var raw in content.Split('\n'))
        {
            var text = raw.Split('#')[0].Split(';')[0].Trim();
            if (text.Length == 0 || text.StartsWith('-') || text.Contains("://") || text.StartsWith('.')) continue;

            var m = line.Match(text);
            if (!m.Success) continue;

            var op = m.Groups[2].Value;
            var version = m.Groups[3].Success ? m.Groups[3].Value.TrimEnd('*').TrimEnd('.') : null;
            if (op is "<" or "<=" or "!=") version = null; // upper bounds say nothing about the installed version
            var exact = op is "==" or "===" && !(m.Groups[3].Value.EndsWith('*'));
            var name = m.Groups[1].Value;
            deps.Add(new ParsedDependency(Ecosystem.PyPI, PackageNames.Normalize(Ecosystem.PyPI, name), name, version,
                exact ? VersionKind.Exact : VersionKind.Declared, isDev, true));
        }
    }

    private static void PythonTomlLock(string content, List<ParsedDependency> deps)
    {
        string? name = null, version = null;
        var local = false;

        void Flush()
        {
            // uv marks the project itself (and path deps) with a non-registry source.
            if (name is not null && version is not null && !local)
            {
                deps.Add(new ParsedDependency(Ecosystem.PyPI, PackageNames.Normalize(Ecosystem.PyPI, name), name, version, VersionKind.Exact, false, false));
            }

            name = version = null;
            local = false;
        }

        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "[[package]]") { Flush(); continue; }
            var m = Regex.Match(line, @"^(name|version)\s*=\s*""([^""]*)""", RegexOptions.None, RegexTimeout);
            if (m.Success)
            {
                if (m.Groups[1].Value == "name") name ??= m.Groups[2].Value;
                else version ??= m.Groups[2].Value;
                continue;
            }

            if (Regex.IsMatch(line, @"^source\s*=\s*\{\s*(editable|virtual|directory|path)\s*=", RegexOptions.None, RegexTimeout)) local = true;
        }

        Flush();
    }

    private static void PipfileLock(string content, List<ParsedDependency> deps)
    {
        using var doc = JsonDocument.Parse(content, JsonOptions);
        foreach (var (section, dev) in new[] { ("default", false), ("develop", true) })
        {
            if (!doc.RootElement.TryGetProperty(section, out var el) || el.ValueKind != JsonValueKind.Object) continue;
            foreach (var p in el.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object
                    || !p.Value.TryGetProperty("version", out var v) || v.ValueKind != JsonValueKind.String) continue;
                var version = v.GetString()!.TrimStart('=', ' ');
                deps.Add(new ParsedDependency(Ecosystem.PyPI, PackageNames.Normalize(Ecosystem.PyPI, p.Name), p.Name, version, VersionKind.Exact, dev, false));
            }
        }
    }

    // ---------------------------------------------------------------- NuGet

    private static XDocument LoadXml(string content) =>
        XDocument.Load(XmlReader.Create(new StringReader(content), new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
        }));

    private static (string? Version, VersionKind Kind) ResolveNuGetVersion(string? spec)
    {
        if (string.IsNullOrWhiteSpace(spec) || spec.Contains("$(")) return (null, VersionKind.Declared);
        var s = spec.Trim();
        var bracketed = s.StartsWith('[') || s.StartsWith('(');
        if (bracketed)
        {
            var inner = s.Trim('[', ']', '(', ')').Split(',')[0].Trim();
            return inner.Length == 0 ? (null, VersionKind.Declared)
                : (inner, s.StartsWith('[') && !s.Contains(',') ? VersionKind.Exact : VersionKind.Declared);
        }

        if (s.Contains('*')) return (s.Replace("*", "0").TrimEnd('-'), VersionKind.Declared);
        return (s, VersionKind.Exact);
    }

    private static void NuGetXml(string content, List<ParsedDependency> deps)
    {
        var doc = LoadXml(content);
        foreach (var el in doc.Descendants())
        {
            var local = el.Name.LocalName;
            string? name = null;
            string? version = null;
            var dev = false;

            if (local is "PackageReference" or "PackageVersion" or "GlobalPackageReference")
            {
                name = (string?)el.Attribute("Include") ?? (string?)el.Attribute("Update");
                version = (string?)el.Attribute("Version") ?? (string?)el.Attribute("VersionOverride")
                    ?? el.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value;
                dev = ((string?)el.Attribute("PrivateAssets") ?? el.Elements().FirstOrDefault(e => e.Name.LocalName == "PrivateAssets")?.Value)
                    ?.Contains("all", StringComparison.OrdinalIgnoreCase) == true;
            }
            else if (local == "package" && el.Attribute("id") is not null)
            {
                name = (string?)el.Attribute("id");
                version = (string?)el.Attribute("version");
                dev = (string?)el.Attribute("developmentDependency") == "true";
            }

            if (string.IsNullOrWhiteSpace(name) || name.Contains("$(")) continue;
            var (v, kind) = ResolveNuGetVersion(version);
            deps.Add(new ParsedDependency(Ecosystem.NuGet, PackageNames.Normalize(Ecosystem.NuGet, name), name, v, kind, dev, true));
        }
    }

    // ---------------------------------------------------------------- Go

    private static void GoMod(string content, List<ParsedDependency> deps)
    {
        var entry = new Regex(@"^\s*([^\s]+)\s+(v[^\s]+)(\s*//\s*indirect)?", RegexOptions.Compiled, RegexTimeout);
        var inRequire = false;
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("require (")) { inRequire = true; continue; }
            if (inRequire && line.StartsWith(')')) { inRequire = false; continue; }

            string? candidate = null;
            if (inRequire) candidate = line;
            else if (line.StartsWith("require ")) candidate = line["require ".Length..];
            if (candidate is null || candidate.StartsWith("//")) continue;

            var m = entry.Match(candidate);
            if (!m.Success) continue;
            var name = m.Groups[1].Value;
            var version = m.Groups[2].Value.Replace("+incompatible", "");
            deps.Add(new ParsedDependency(Ecosystem.Go, PackageNames.Normalize(Ecosystem.Go, name), name, version, VersionKind.Exact, false, !m.Groups[3].Success));
        }
    }

    // ---------------------------------------------------------------- Cargo

    private static void CargoLock(string content, List<ParsedDependency> deps)
    {
        string? name = null, version = null;
        var hasSource = false;

        void Flush()
        {
            // Packages without a source are workspace members, i.e. the project itself.
            if (name is not null && version is not null && hasSource)
            {
                deps.Add(new ParsedDependency(Ecosystem.Cargo, PackageNames.Normalize(Ecosystem.Cargo, name), name, version, VersionKind.Exact, false, false));
            }

            name = version = null;
            hasSource = false;
        }

        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "[[package]]") { Flush(); continue; }
            var m = Regex.Match(line, @"^(name|version|source)\s*=\s*""([^""]*)""", RegexOptions.None, RegexTimeout);
            if (!m.Success) continue;
            switch (m.Groups[1].Value)
            {
                case "name": name = m.Groups[2].Value; break;
                case "version": version = m.Groups[2].Value; break;
                case "source": hasSource = true; break;
            }
        }

        Flush();
    }

    private static void CargoToml(string content, List<ParsedDependency> deps)
    {
        var section = "";
        var tableName = (string?)null;
        var tableDev = false;
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('['))
            {
                section = line.Trim('[', ']').Trim();
                tableName = null;
                var m = Regex.Match(section, @"^(?:[\w.\-]+\.)?(dependencies|dev-dependencies|build-dependencies)\.([\w\-]+)$", RegexOptions.None, RegexTimeout);
                if (m.Success)
                {
                    tableName = m.Groups[2].Value;
                    tableDev = m.Groups[1].Value != "dependencies";
                }

                continue;
            }

            if (tableName is not null)
            {
                var vm = Regex.Match(line, @"^version\s*=\s*""([^""]+)""", RegexOptions.None, RegexTimeout);
                if (vm.Success) AddCargo(deps, tableName, vm.Groups[1].Value, tableDev);
                continue;
            }

            if (!Regex.IsMatch(section, @"(^|\.)(dependencies|dev-dependencies|build-dependencies)$", RegexOptions.None, RegexTimeout)) continue;
            var dev = section.Contains("dev-dependencies");
            var simple = Regex.Match(line, @"^([\w\-]+)\s*=\s*""([^""]+)""", RegexOptions.None, RegexTimeout);
            if (simple.Success) { AddCargo(deps, simple.Groups[1].Value, simple.Groups[2].Value, dev); continue; }
            var table = Regex.Match(line, @"^([\w\-]+)\s*=\s*\{[^}]*version\s*=\s*""([^""]+)""", RegexOptions.None, RegexTimeout);
            if (table.Success) AddCargo(deps, table.Groups[1].Value, table.Groups[2].Value, dev);
        }
    }

    private static void AddCargo(List<ParsedDependency> deps, string name, string spec, bool dev)
    {
        var exact = spec.StartsWith('=');
        var version = spec.TrimStart('^', '~', '=', '>', ' ').Split(',')[0].Trim();
        if (!Regex.IsMatch(version, @"^\d", RegexOptions.None, RegexTimeout)) return;
        deps.Add(new ParsedDependency(Ecosystem.Cargo, PackageNames.Normalize(Ecosystem.Cargo, name), name, version,
            exact ? VersionKind.Exact : VersionKind.Declared, dev, true));
    }

    // ---------------------------------------------------------------- Maven

    private static void Pom(string content, List<ParsedDependency> deps)
    {
        var doc = LoadXml(content);
        var props = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in doc.Descendants().Where(e => e.Name.LocalName == "properties").SelectMany(e => e.Elements()))
        {
            props[p.Name.LocalName] = p.Value.Trim();
        }

        var projectVersion = doc.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "version")?.Value.Trim();
        if (projectVersion is not null) { props["project.version"] = projectVersion; props["version"] = projectVersion; }

        string? Resolve(string? value)
        {
            if (value is null) return null;
            for (var i = 0; i < 5 && value.Contains("${"); i++)
            {
                value = Regex.Replace(value, @"\$\{([^}]+)\}", m => props.TryGetValue(m.Groups[1].Value, out var r) ? r : m.Value, RegexOptions.None, RegexTimeout);
            }

            return value.Contains("${") ? null : value;
        }

        string? Child(XElement e, string name) => e.Elements().FirstOrDefault(c => c.Name.LocalName == name)?.Value.Trim();

        var managed = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in doc.Descendants().Where(e => e.Name.LocalName == "dependency"))
        {
            if (!d.Ancestors().Any(a => a.Name.LocalName == "dependencyManagement")) continue;
            managed[$"{Child(d, "groupId")}:{Child(d, "artifactId")}"] = Resolve(Child(d, "version"));
        }

        foreach (var d in doc.Descendants().Where(e => e.Name.LocalName == "dependency"))
        {
            if (d.Ancestors().Any(a => a.Name.LocalName is "dependencyManagement" or "plugin" or "plugins" or "pluginManagement")) continue;

            var group = Resolve(Child(d, "groupId"));
            var artifact = Resolve(Child(d, "artifactId"));
            if (string.IsNullOrEmpty(group) || string.IsNullOrEmpty(artifact)) continue;

            var key = $"{group}:{artifact}";
            var version = Resolve(Child(d, "version")) ?? (managed.TryGetValue(key, out var m) ? m : null);
            var kind = VersionKind.Exact;
            if (version is not null && (version.StartsWith('[') || version.StartsWith('(')))
            {
                kind = version.StartsWith('[') && !version.Contains(',') ? VersionKind.Exact : VersionKind.Declared;
                version = version.Trim('[', ']', '(', ')').Split(',')[0].Trim();
                if (version.Length == 0) version = null;
            }

            var scope = Child(d, "scope");
            deps.Add(new ParsedDependency(Ecosystem.Maven, PackageNames.Normalize(Ecosystem.Maven, key), key, version, kind, scope == "test", true));
        }
    }

    // ---------------------------------------------------------------- SBOM

    private static void Sbom(string content, List<ParsedDependency> deps, List<string> warnings, string fileName)
    {
        using var doc = JsonDocument.Parse(content, JsonOptions);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            warnings.Add($"{fileName}: unsupported file type.");
            return;
        }

        var purls = new List<string>();
        if (root.TryGetProperty("bomFormat", out var fmt) && fmt.GetString() == "CycloneDX")
        {
            CollectCycloneDx(root, purls, 0);
        }
        else if (root.TryGetProperty("spdxVersion", out _) && root.TryGetProperty("packages", out var pkgs) && pkgs.ValueKind == JsonValueKind.Array)
        {
            foreach (var p in pkgs.EnumerateArray())
            {
                if (!p.TryGetProperty("externalRefs", out var refs) || refs.ValueKind != JsonValueKind.Array) continue;
                foreach (var r in refs.EnumerateArray())
                {
                    if (r.TryGetProperty("referenceType", out var rt) && rt.GetString() == "purl"
                        && r.TryGetProperty("referenceLocator", out var loc) && loc.ValueKind == JsonValueKind.String)
                    {
                        purls.Add(loc.GetString()!);
                    }
                }
            }
        }
        else
        {
            warnings.Add($"{fileName}: unsupported JSON file (expected CycloneDX or SPDX).");
            return;
        }

        foreach (var purl in purls)
        {
            if (TryParsePurl(purl, out var dep)) deps.Add(dep);
        }
    }

    private static void CollectCycloneDx(JsonElement element, List<string> purls, int depth)
    {
        if (depth > 40 || !element.TryGetProperty("components", out var comps) || comps.ValueKind != JsonValueKind.Array) return;
        foreach (var c in comps.EnumerateArray())
        {
            if (c.TryGetProperty("purl", out var p) && p.ValueKind == JsonValueKind.String) purls.Add(p.GetString()!);
            CollectCycloneDx(c, purls, depth + 1);
        }
    }

    public static bool TryParsePurl(string purl, out ParsedDependency dependency)
    {
        dependency = null!;
        if (!purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return false;

        var body = purl[4..].Split('#')[0].Split('?')[0];
        var at = body.LastIndexOf('@');
        if (at < 0) return false;
        var version = Uri.UnescapeDataString(body[(at + 1)..]);
        var path = body[..at];
        var slash = path.IndexOf('/');
        if (slash < 0) return false;

        var type = path[..slash].ToLowerInvariant();
        var parts = path[(slash + 1)..].Split('/').Select(Uri.UnescapeDataString).ToArray();
        var name = parts[^1];
        var ns = parts.Length > 1 ? string.Join('/', parts[..^1]) : null;

        (Ecosystem eco, string full)? mapped = type switch
        {
            "npm" => (Ecosystem.Npm, ns is null ? name : $"{ns}/{name}"),
            "nuget" => (Ecosystem.NuGet, name),
            "pypi" => (Ecosystem.PyPI, name),
            "maven" when ns is not null => (Ecosystem.Maven, $"{ns}:{name}"),
            "cargo" => (Ecosystem.Cargo, name),
            "golang" => (Ecosystem.Go, ns is null ? name : $"{ns}/{name}"),
            _ => null,
        };
        if (mapped is null || version.Length == 0) return false;

        var (e, n) = mapped.Value;
        dependency = new ParsedDependency(e, PackageNames.Normalize(e, n), n, version, VersionKind.Exact, false, false);
        return true;
    }
}

/// <summary>Combines the dependencies from several files of one project into a single set.</summary>
public static class DependencyMerger
{
    public const int MaxDependencies = 10_000;

    public static IReadOnlyList<ParsedDependency> Merge(IEnumerable<ParsedDependency> parsed)
    {
        var result = new List<ParsedDependency>();
        foreach (var group in parsed.GroupBy(d => (d.Ecosystem, d.Name)))
        {
            var direct = group.Any(d => d.IsDirect);
            var dev = group.All(d => d.IsDev);
            var exact = group.Where(d => d.Kind == VersionKind.Exact && d.Version is not null).ToList();
            // Exact versions (from lockfiles) beat declared ranges for the same package.
            var chosen = exact.Count > 0 ? exact : group.ToList();

            foreach (var version in chosen.Select(d => d.Version).Distinct())
            {
                var pick = chosen.First(d => d.Version == version);
                result.Add(pick with { IsDirect = direct, IsDev = dev });
            }
        }

        return result;
    }
}
