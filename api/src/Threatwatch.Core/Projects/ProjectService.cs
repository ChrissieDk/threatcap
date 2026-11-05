using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Projects;

public record ProjectFileInput(string? Name, string? Content);

public record ProjectFindingDto(
    Guid VulnerabilityId,
    string CanonicalId,
    string Title,
    Severity Severity,
    decimal? CvssScore,
    double? EpssScore,
    bool IsKnownExploited,
    double? PriorityScore,
    Ecosystem Ecosystem,
    string Package,
    string Version,
    VersionKind VersionKind,
    bool IsDirect,
    bool IsDev,
    string? FixedIn);

public record ProjectDependencyDto(
    Ecosystem Ecosystem, string Name, string? Version, VersionKind VersionKind, bool IsDirect, bool IsDev);

public record ProjectSummaryDto(
    Guid Id,
    string Name,
    int DependencyCount,
    int DirectCount,
    int UncheckedCount,
    int FindingCount,
    int CriticalHighCount,
    int KnownExploitedCount,
    IReadOnlyList<string> SourceFiles,
    DateTimeOffset UpdatedAt);

public record ProjectDetailDto(
    ProjectSummaryDto Summary,
    IReadOnlyList<ProjectFindingDto> Findings,
    IReadOnlyList<ProjectDependencyDto> Dependencies);

public record ProjectFindingWithProjectDto(Guid ProjectId, string ProjectName, ProjectFindingDto Finding);

public record ProjectOverviewDto(
    int ProjectCount,
    int ProjectsAffected,
    int FindingCount,
    int CriticalHighCount,
    int KnownExploitedCount,
    IReadOnlyList<ProjectFindingWithProjectDto> Top);

public record ProjectUploadResultDto(Guid Id, int DependencyCount, IReadOnlyList<string> Warnings);

/// <summary>A project dependency flattened for matching (used by alerts too).</summary>
public record ProjectDep(
    Guid ProjectId,
    string ProjectName,
    Ecosystem Ecosystem,
    string Name,
    string DisplayName,
    string? Version,
    VersionKind VersionKind,
    bool IsDirect,
    bool IsDev);

public class ProjectService(ThreatwatchDbContext db)
{
    public const int MaxProjectsPerUser = 20;
    public const int MaxFilesPerUpload = 10;
    public const int MaxFileBytes = 5_000_000;
    public const int MaxTotalBytes = 8_000_000;
    public const int MaxRawDependencies = 20_000;
    private const int QueryChunk = 1000;

    public async Task<IReadOnlyList<ProjectSummaryDto>> ListAsync(Guid userId, CancellationToken ct)
    {
        var projects = await db.Projects.AsNoTracking()
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.UpdatedAt)
            .ToListAsync(ct);
        var deps = await LoadMergedAsync(db, [userId], ct);
        var findings = await ComputeFindingsAsync(db, deps.Values.SelectMany(d => d).ToList(), ct);
        var files = await SourceFilesAsync(projects.Select(p => p.Id).ToList(), ct);

        return projects.Select(p =>
        {
            var projectDeps = deps.TryGetValue(userId, out var all) ? all.Where(d => d.ProjectId == p.Id).ToList() : [];
            return Summarize(p, projectDeps, findings.Where(f => f.ProjectId == p.Id).Select(f => f.Finding).ToList(), files.GetValueOrDefault(p.Id) ?? []);
        }).ToList();
    }

    /// <summary>Cross-project rollup for the Overview and Act now pages.</summary>
    public async Task<ProjectOverviewDto> OverviewAsync(Guid userId, int top, CancellationToken ct)
    {
        var projectCount = await db.Projects.CountAsync(p => p.UserId == userId, ct);
        if (projectCount == 0) return new ProjectOverviewDto(0, 0, 0, 0, 0, []);

        var deps = (await LoadMergedAsync(db, [userId], ct)).GetValueOrDefault(userId) ?? [];
        var names = deps.GroupBy(d => d.ProjectId).ToDictionary(g => g.Key, g => g.First().ProjectName);
        // One entry per vulnerability per project, however many packages or versions it hits.
        var findings = (await ComputeFindingsAsync(db, deps, ct))
            .GroupBy(f => (f.ProjectId, f.Finding.VulnerabilityId))
            .Select(g => g.OrderByDescending(x => x.Finding.IsDirect).First())
            .ToList();

        var ordered = findings
            .OrderByDescending(f => f.Finding.IsKnownExploited)
            .ThenByDescending(f => f.Finding.PriorityScore ?? 0)
            .ThenByDescending(f => f.Finding.Severity)
            .ToList();

        return new ProjectOverviewDto(
            projectCount,
            findings.Select(f => f.ProjectId).Distinct().Count(),
            findings.Count,
            findings.Count(f => f.Finding.Severity >= Severity.High),
            findings.Count(f => f.Finding.IsKnownExploited),
            ordered.Take(Math.Clamp(top, 1, 50))
                .Select(f => new ProjectFindingWithProjectDto(f.ProjectId, names.GetValueOrDefault(f.ProjectId, ""), f.Finding))
                .ToList());
    }

    public async Task<ProjectDetailDto?> GetAsync(Guid userId, Guid projectId, CancellationToken ct)
    {
        var project = await db.Projects.AsNoTracking().FirstOrDefaultAsync(p => p.Id == projectId && p.UserId == userId, ct);
        if (project is null) return null;

        var deps = (await LoadMergedAsync(db, [userId], ct)).GetValueOrDefault(userId)?.Where(d => d.ProjectId == projectId).ToList() ?? [];
        var findings = (await ComputeFindingsAsync(db, deps, ct)).Select(f => f.Finding)
            .OrderByDescending(f => f.IsKnownExploited)
            .ThenByDescending(f => f.PriorityScore ?? 0)
            .ThenByDescending(f => f.Severity)
            .ToList();
        var files = (await SourceFilesAsync([projectId], ct)).GetValueOrDefault(projectId) ?? [];

        var listed = deps
            .OrderByDescending(d => d.IsDirect).ThenBy(d => d.Name)
            .Take(1000)
            .Select(d => new ProjectDependencyDto(d.Ecosystem, d.DisplayName, d.Version, d.VersionKind, d.IsDirect, d.IsDev))
            .ToList();
        return new ProjectDetailDto(Summarize(project, deps, findings, files), findings, listed);
    }

    public async Task<(ProjectUploadResultDto? Result, string? Error)> CreateAsync(
        Guid userId, string? name, IReadOnlyList<ProjectFileInput>? files, CancellationToken ct)
    {
        var trimmed = name?.Trim() ?? "";
        if (trimmed.Length is 0 or > 80) return (null, "Project name is required (at most 80 characters).");
        if (await db.Projects.CountAsync(p => p.UserId == userId, ct) >= MaxProjectsPerUser)
        {
            return (null, $"You can have at most {MaxProjectsPerUser} projects.");
        }

        var (parsed, warnings, error) = ParseUpload(files);
        if (error is not null) return (null, error);

        var now = DateTimeOffset.UtcNow;
        var project = new Project { Id = Guid.NewGuid(), UserId = userId, Name = trimmed, CreatedAt = now, UpdatedAt = now };
        db.Projects.Add(project);
        db.ProjectDependencies.AddRange(parsed.Select(p => ToEntity(project.Id, p.File, p.Dep)));
        await db.SaveChangesAsync(ct);

        var merged = DependencyMerger.Merge(parsed.Select(p => p.Dep));
        return (new ProjectUploadResultDto(project.Id, merged.Count, warnings), null);
    }

    /// <summary>Adds files to a project; a file with the same name as an existing one replaces it.</summary>
    public async Task<(ProjectUploadResultDto? Result, string? Error, bool Found)> UpdateFilesAsync(
        Guid userId, Guid projectId, IReadOnlyList<ProjectFileInput>? files, CancellationToken ct)
    {
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId && p.UserId == userId, ct);
        if (project is null) return (null, null, false);

        var (parsed, warnings, error) = ParseUpload(files);
        if (error is not null) return (null, error, true);

        var uploadedNames = (files ?? []).Select(f => FileLabel(f.Name)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var existing = (await db.ProjectDependencies.Where(d => d.ProjectId == projectId).ToListAsync(ct))
            .Where(d => uploadedNames.Contains(d.SourceFile, StringComparer.OrdinalIgnoreCase))
            .ToList();
        db.ProjectDependencies.RemoveRange(existing);

        var total = await db.ProjectDependencies.CountAsync(d => d.ProjectId == projectId, ct) - existing.Count + parsed.Count;
        if (total > MaxRawDependencies) return (null, $"A project can have at most {MaxRawDependencies} dependency entries.", true);

        db.ProjectDependencies.AddRange(parsed.Select(p => ToEntity(projectId, p.File, p.Dep)));
        project.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        var count = (await LoadMergedAsync(db, [userId], ct)).GetValueOrDefault(userId)?.Count(d => d.ProjectId == projectId) ?? 0;
        return (new ProjectUploadResultDto(projectId, count, warnings), null, true);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid projectId, CancellationToken ct)
    {
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId && p.UserId == userId, ct);
        if (project is null) return false;
        db.Projects.Remove(project);
        await db.SaveChangesAsync(ct);
        return true;
    }

    // ---------------------------------------------------------------- shared helpers

    /// <summary>Every project dependency of the given users, merged across each project's files.</summary>
    public static async Task<Dictionary<Guid, List<ProjectDep>>> LoadMergedAsync(
        ThreatwatchDbContext db, IReadOnlyCollection<Guid> userIds, CancellationToken ct)
    {
        var rows = await db.ProjectDependencies.AsNoTracking()
            .Where(d => userIds.Contains(d.Project.UserId))
            .Select(d => new
            {
                d.ProjectId, ProjectName = d.Project.Name, d.Project.UserId,
                d.Ecosystem, d.Name, d.DisplayName, d.Version, d.VersionKind, d.IsDev, d.IsDirect,
            })
            .ToListAsync(ct);

        var result = new Dictionary<Guid, List<ProjectDep>>();
        foreach (var project in rows.GroupBy(r => r.ProjectId))
        {
            var first = project.First();
            var parsed = project.Select(r => new ParsedDependency(r.Ecosystem, r.Name, r.DisplayName, r.Version, r.VersionKind, r.IsDev, r.IsDirect));
            var merged = DependencyMerger.Merge(parsed)
                .Select(m => new ProjectDep(first.ProjectId, first.ProjectName, m.Ecosystem, m.Name, m.DisplayName, m.Version, m.Kind, m.IsDirect, m.IsDev));
            if (!result.TryGetValue(first.UserId, out var list)) result[first.UserId] = list = [];
            list.AddRange(merged);
        }

        return result;
    }

    /// <summary>Checks dependencies with a known version against the stored advisories.</summary>
    public static async Task<List<(Guid ProjectId, ProjectFindingDto Finding)>> ComputeFindingsAsync(
        ThreatwatchDbContext db, IReadOnlyList<ProjectDep> deps, CancellationToken ct)
    {
        var output = new List<(Guid, ProjectFindingDto)>();
        foreach (var byEco in deps.Where(d => d.Version is not null).GroupBy(d => d.Ecosystem))
        {
            var names = byEco.Select(d => d.Name).Distinct().ToList();
            for (var i = 0; i < names.Count; i += QueryChunk)
            {
                var chunk = names.Skip(i).Take(QueryChunk).ToList();
                var eco = byEco.Key;
                var candidates = await db.AffectedPackages.AsNoTracking()
                    .Where(p => p.Ecosystem == eco && chunk.Contains(p.PackageName) && !p.Vulnerability.IsWithdrawn)
                    .Select(p => new
                    {
                        p.PackageName, p.AffectedRanges,
                        v = new { p.Vulnerability.Id, p.Vulnerability.CanonicalId, p.Vulnerability.Title, p.Vulnerability.Severity,
                                  p.Vulnerability.CvssScore, p.Vulnerability.EpssScore, p.Vulnerability.IsKnownExploited, p.Vulnerability.PriorityScore },
                    })
                    .ToListAsync(ct);

                var byName = candidates.ToLookup(c => c.PackageName);
                var seen = new HashSet<(Guid, Guid, string)>();
                foreach (var dep in byEco.Where(d => chunk.Contains(d.Name)))
                {
                    foreach (var c in byName[dep.Name])
                    {
                        var result = OsvRangeEvaluator.Evaluate(eco, c.AffectedRanges, dep.Version);
                        if (result.Verdict != RangeVerdict.Affected) continue;
                        if (!seen.Add((dep.ProjectId, c.v.Id, dep.Name + "@" + dep.Version))) continue;

                        output.Add((dep.ProjectId, new ProjectFindingDto(
                            c.v.Id, c.v.CanonicalId, c.v.Title, c.v.Severity, c.v.CvssScore, c.v.EpssScore,
                            c.v.IsKnownExploited, c.v.PriorityScore, eco, dep.DisplayName, dep.Version!,
                            dep.VersionKind, dep.IsDirect, dep.IsDev, result.FixedIn)));
                    }
                }
            }
        }

        return output;
    }

    private static ProjectSummaryDto Summarize(
        Project p, List<ProjectDep> deps, List<ProjectFindingDto> findings, IReadOnlyList<string> files) =>
        new(p.Id, p.Name, deps.Count, deps.Count(d => d.IsDirect), deps.Count(d => d.Version is null),
            findings.Select(f => f.VulnerabilityId).Distinct().Count(),
            findings.Where(f => f.Severity >= Severity.High).Select(f => f.VulnerabilityId).Distinct().Count(),
            findings.Where(f => f.IsKnownExploited).Select(f => f.VulnerabilityId).Distinct().Count(),
            files, p.UpdatedAt);

    private async Task<Dictionary<Guid, IReadOnlyList<string>>> SourceFilesAsync(IReadOnlyCollection<Guid> projectIds, CancellationToken ct) =>
        (await db.ProjectDependencies.AsNoTracking()
            .Where(d => projectIds.Contains(d.ProjectId))
            .Select(d => new { d.ProjectId, d.SourceFile })
            .Distinct()
            .ToListAsync(ct))
        .GroupBy(x => x.ProjectId)
        .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(x => x.SourceFile).Order().ToList());

    private static string FileLabel(string? name)
    {
        var label = Path.GetFileName((name ?? "").Replace('\\', '/'));
        return label.Length > 200 ? label[..200] : label;
    }

    private static ProjectDependency ToEntity(Guid projectId, string file, ParsedDependency d) => new()
    {
        Id = Guid.NewGuid(),
        ProjectId = projectId,
        SourceFile = file,
        Ecosystem = d.Ecosystem,
        Name = Truncate(d.Name, 300),
        DisplayName = Truncate(d.DisplayName, 300),
        Version = d.Version is null ? null : Truncate(d.Version, 100),
        VersionKind = d.Kind,
        IsDev = d.IsDev,
        IsDirect = d.IsDirect,
    };

    private static string Truncate(string v, int max) => v.Length <= max ? v : v[..max];

    private static (List<(string File, ParsedDependency Dep)> Parsed, List<string> Warnings, string? Error) ParseUpload(
        IReadOnlyList<ProjectFileInput>? files)
    {
        var parsed = new List<(string, ParsedDependency)>();
        var warnings = new List<string>();
        if (files is null || files.Count == 0) return (parsed, warnings, "Add at least one dependency file.");
        if (files.Count > MaxFilesPerUpload) return (parsed, warnings, $"Upload at most {MaxFilesPerUpload} files at a time.");

        long total = 0;
        foreach (var file in files)
        {
            var label = FileLabel(file.Name);
            if (label.Length == 0) return (parsed, warnings, "Every file needs a name.");
            var content = file.Content ?? "";
            total += content.Length;
            if (content.Length > MaxFileBytes) return (parsed, warnings, $"{label} is larger than {MaxFileBytes / 1_000_000} MB.");

            var result = DependencyFileParser.Parse(label, content);
            warnings.AddRange(result.Warnings);
            parsed.AddRange(result.Dependencies.Select(d => (label, d)));
        }

        if (total > MaxTotalBytes) return (parsed, warnings, $"Files are larger than {MaxTotalBytes / 1_000_000} MB in total.");
        if (parsed.Count > MaxRawDependencies) return (parsed, warnings, $"Too many dependencies (limit {MaxRawDependencies}).");
        if (parsed.Count == 0) return (parsed, warnings, warnings.FirstOrDefault() ?? "No dependencies were found in the files.");
        return (parsed, warnings, null);
    }
}
