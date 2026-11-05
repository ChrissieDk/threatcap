using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Projects;

namespace Threatwatch.Tests;

public class ProjectServiceTests : IDisposable
{
    private const string Ranges = """[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]""";

    private readonly ThreatwatchDbContext _db;
    private readonly ProjectService _projects;
    private readonly Guid _userId = Guid.NewGuid();

    public ProjectServiceTests()
    {
        _db = new ThreatwatchDbContext(new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        _projects = new ProjectService(_db);
        _db.Users.Add(new UserAccount
        {
            Id = _userId, Email = "dev@example.com", UserName = "dev@example.com",
            DisplayName = "Dev", CreatedAt = DateTimeOffset.UtcNow,
        });
        AddVuln("GHSA-lodash", "lodash", Severity.High, Ranges, kev: true);
        AddVuln("GHSA-express", "express", Severity.Critical, """[{"type":"SEMVER","events":[{"introduced":"5.0.0"},{"fixed":"5.1.0"}]}]""");
        _db.SaveChanges();
    }

    public void Dispose() => _db.Dispose();

    private void AddVuln(string id, string package, Severity severity, string ranges, bool kev = false)
    {
        var v = new Vulnerability
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, Severity = severity, IsKnownExploited = kev,
            PublishedAt = DateTimeOffset.UtcNow.AddHours(-1), ModifiedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
        };
        v.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(), VulnerabilityId = v.Id, Ecosystem = Ecosystem.Npm,
            PackageName = package, DisplayName = package, AffectedRanges = ranges, FixedVersions = ["4.17.21"],
        });
        _db.Vulnerabilities.Add(v);
    }

    private static ProjectFileInput File(string name, string content) => new(name, content);

    [Fact]
    public async Task Reports_only_version_affected_findings_with_fix()
    {
        var (created, error) = await _projects.CreateAsync(_userId, "web", [
            File("package.json", """{"dependencies":{"lodash":"^4.17.0","express":"^4.18.0"}}"""),
            File("package-lock.json", """{"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/express":{"version":"4.18.2"}}}"""),
        ], default);
        Assert.Null(error);

        var detail = (await _projects.GetAsync(_userId, created!.Id, default))!;
        var finding = Assert.Single(detail.Findings);
        Assert.Equal("GHSA-lodash", finding.CanonicalId);
        Assert.Equal("4.17.20", finding.Version);
        Assert.Equal("4.17.21", finding.FixedIn);
        Assert.Equal(VersionKind.Exact, finding.VersionKind);
        Assert.Equal((1, 1, 1), (detail.Summary.FindingCount, detail.Summary.CriticalHighCount, detail.Summary.KnownExploitedCount));
    }

    [Fact]
    public async Task Declared_range_is_flagged_as_approximate()
    {
        var (created, _) = await _projects.CreateAsync(_userId, "web", [File("package.json", """{"dependencies":{"lodash":"^4.17.0"}}""")], default);
        var finding = Assert.Single((await _projects.GetAsync(_userId, created!.Id, default))!.Findings);
        Assert.Equal(VersionKind.Declared, finding.VersionKind);
    }

    [Fact]
    public async Task Adding_a_lockfile_later_refines_and_same_name_replaces()
    {
        var (created, _) = await _projects.CreateAsync(_userId, "web", [File("package.json", """{"dependencies":{"lodash":"^4.17.0"}}""")], default);
        await _projects.UpdateFilesAsync(_userId, created!.Id,
            [File("package-lock.json", """{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}""")], default);
        Assert.Empty((await _projects.GetAsync(_userId, created.Id, default))!.Findings);

        await _projects.UpdateFilesAsync(_userId, created.Id,
            [File("package-lock.json", """{"packages":{"node_modules/lodash":{"version":"4.17.19"}}}""")], default);
        var detail = (await _projects.GetAsync(_userId, created.Id, default))!;
        Assert.Single(detail.Findings);
        Assert.Equal(["package-lock.json", "package.json"], detail.Summary.SourceFiles);
        Assert.Single(detail.Dependencies);
    }

    [Fact]
    public async Task Overview_rolls_up_findings_across_projects()
    {
        Assert.Equal(0, (await _projects.OverviewAsync(_userId, 5, default)).ProjectCount);

        await _projects.CreateAsync(_userId, "api", [File("package-lock.json",
            """{"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/lodash":{"version":"4.17.10"}}}""")], default);
        await _projects.CreateAsync(_userId, "clean", [File("package-lock.json",
            """{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}""")], default);

        var overview = await _projects.OverviewAsync(_userId, 5, default);
        Assert.Equal((2, 1, 1, 1, 1), (overview.ProjectCount, overview.ProjectsAffected, overview.FindingCount, overview.CriticalHighCount, overview.KnownExploitedCount));
        var top = Assert.Single(overview.Top);
        Assert.Equal("api", top.ProjectName);
        Assert.Equal("GHSA-lodash", top.Finding.CanonicalId);
    }

    [Fact]
    public async Task Users_cannot_see_or_change_each_others_projects()
    {
        var (created, _) = await _projects.CreateAsync(_userId, "web", [File("package.json", """{"dependencies":{"lodash":"4.17.0"}}""")], default);
        var other = Guid.NewGuid();

        Assert.Null(await _projects.GetAsync(other, created!.Id, default));
        Assert.False(await _projects.DeleteAsync(other, created.Id, default));
        Assert.False((await _projects.UpdateFilesAsync(other, created.Id, [File("package.json", "{}")], default)).Found);
        Assert.Empty(await _projects.ListAsync(other, default));
        Assert.Single(await _projects.ListAsync(_userId, default));
    }

    [Fact]
    public async Task Validates_input()
    {
        Assert.NotNull((await _projects.CreateAsync(_userId, "", [File("package.json", "{}")], default)).Error);
        Assert.NotNull((await _projects.CreateAsync(_userId, "x", [], default)).Error);
        Assert.NotNull((await _projects.CreateAsync(_userId, "x", [File("notes.txt", "hello")], default)).Error);
        Assert.NotNull((await _projects.CreateAsync(_userId, "x", [File("package.json", new string(' ', ProjectService.MaxFileBytes + 1))], default)).Error);

        for (var i = 0; i < ProjectService.MaxProjectsPerUser; i++)
        {
            Assert.Null((await _projects.CreateAsync(_userId, $"p{i}", [File("package.json", """{"dependencies":{"a":"1.0.0"}}""")], default)).Error);
        }

        Assert.Contains("at most", (await _projects.CreateAsync(_userId, "one-too-many", [File("package.json", """{"dependencies":{"a":"1.0.0"}}""")], default)).Error);
    }

    [Fact]
    public async Task Alerts_use_version_matching_for_project_dependencies()
    {
        _db.AlertPreferences.Add(new AlertPreference
        {
            Id = Guid.NewGuid(), UserId = _userId, MinSeverity = Severity.High,
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1), UpdatedAt = DateTimeOffset.UtcNow,
        });
        _db.AlertChannels.Add(new AlertChannel
        {
            Id = Guid.NewGuid(), UserId = _userId, Type = AlertChannelType.Webhook, Label = "hook", CreatedAt = DateTimeOffset.UtcNow,
        });
        await _db.SaveChangesAsync();
        await _projects.CreateAsync(_userId, "api", [File("package-lock.json",
            """{"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/express":{"version":"4.18.2"}}}""")], default);

        var alerts = new AlertService(_db, new EphemeralDataProtectionProvider(), Options.Create(new AlertOptions()));
        Assert.Equal(1, await alerts.EnqueueAsync(default));

        var delivery = _db.AlertDeliveries.Single();
        Assert.Contains("GHSA-lodash", delivery.Title);
        Assert.Contains("api: lodash 4.17.20 (fixed in 4.17.21)", delivery.Summary);
    }
}
