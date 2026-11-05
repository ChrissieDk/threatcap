using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Projects;
using Threatwatch.Core.Services;

namespace Threatwatch.Tests;

public class NotificationRelevanceTests : IDisposable
{
    private const string Ranges = """[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]""";

    private readonly ThreatwatchDbContext _db;
    private readonly NotificationService _notifications;
    private readonly Guid _userId = Guid.NewGuid();

    public NotificationRelevanceTests()
    {
        _db = new ThreatwatchDbContext(new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        _db.Users.Add(new UserAccount
        {
            Id = _userId, Email = "dev@example.com", UserName = "dev@example.com",
            DisplayName = "Dev", CreatedAt = DateTimeOffset.UtcNow,
        });
        _notifications = new NotificationService(_db);
    }

    public void Dispose() => _db.Dispose();

    private Technology Follow(string name, TechnologyType type, Ecosystem? eco)
    {
        var tech = new Technology
        {
            Id = Guid.NewGuid(), Name = name, Slug = name.ToLowerInvariant(), Type = type, Ecosystem = eco, Aliases = [],
        };
        _db.Technologies.Add(tech);
        _db.UserFollows.Add(new UserFollow { Id = Guid.NewGuid(), UserId = _userId, TechnologyId = tech.Id, CreatedAt = DateTimeOffset.UtcNow });
        _db.SaveChanges();
        return tech;
    }

    private void AddVuln(string id, string package, Severity severity, bool kev = false, int hoursAgo = 2)
    {
        var v = new Vulnerability
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, Severity = severity, IsKnownExploited = kev,
            PublishedAt = DateTimeOffset.UtcNow.AddHours(-hoursAgo), ModifiedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
        };
        v.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(), VulnerabilityId = v.Id, Ecosystem = Ecosystem.Npm,
            PackageName = package, DisplayName = package, AffectedRanges = Ranges,
        });
        _db.Vulnerabilities.Add(v);
        _db.SaveChanges();
    }

    [Fact]
    public async Task Low_and_medium_advisories_for_a_specific_follow_are_not_notified()
    {
        Follow("lodash", TechnologyType.Package, Ecosystem.Npm);
        AddVuln("LOW", "lodash", Severity.Low);
        AddVuln("MEDIUM", "lodash", Severity.Medium);
        AddVuln("HIGH", "lodash", Severity.High);

        var summary = await _notifications.GetAsync(_userId, default);
        Assert.Equal(["HIGH"], summary.Items.Select(i => i.CanonicalId));
    }

    [Fact]
    public async Task Users_alert_rules_are_applied_to_the_bell()
    {
        Follow("lodash", TechnologyType.Package, Ecosystem.Npm);
        AddVuln("MEDIUM", "lodash", Severity.Medium);
        _db.AlertPreferences.Add(new AlertPreference
        {
            Id = Guid.NewGuid(), UserId = _userId, MinSeverity = Severity.Medium, CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
        });
        _db.SaveChanges();

        Assert.Single((await _notifications.GetAsync(_userId, default)).Items);
    }

    [Fact]
    public async Task Whole_ecosystem_follows_only_notify_for_kev_or_critical()
    {
        Follow("npm", TechnologyType.Ecosystem, Ecosystem.Npm);
        AddVuln("HIGH", "left-pad", Severity.High);
        AddVuln("CRITICAL", "right-pad", Severity.Critical);
        AddVuln("KEV", "mid-pad", Severity.Medium, kev: true);

        var ids = (await _notifications.GetAsync(_userId, default)).Items.Select(i => i.CanonicalId).Order().ToArray();
        Assert.Equal(["CRITICAL", "KEV"], ids);
    }

    [Fact]
    public async Task A_version_affected_project_dependency_always_notifies_and_ranks_first()
    {
        Follow("lodash", TechnologyType.Package, Ecosystem.Npm);
        AddVuln("CRITICAL-FOLLOWED", "lodash", Severity.Critical);
        AddVuln("LOW-IN-PROJECT", "mypkg", Severity.Low);
        AddVuln("LOW-FIXED-VERSION", "otherpkg", Severity.Low);

        var project = new Project { Id = Guid.NewGuid(), UserId = _userId, Name = "api", CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow };
        _db.Projects.Add(project);
        _db.ProjectDependencies.AddRange(
            new ProjectDependency { Id = Guid.NewGuid(), ProjectId = project.Id, SourceFile = "package-lock.json", Ecosystem = Ecosystem.Npm, Name = "mypkg", DisplayName = "mypkg", Version = "1.0.0", VersionKind = VersionKind.Exact, IsDirect = true },
            new ProjectDependency { Id = Guid.NewGuid(), ProjectId = project.Id, SourceFile = "package-lock.json", Ecosystem = Ecosystem.Npm, Name = "otherpkg", DisplayName = "otherpkg", Version = "2.0.0", VersionKind = VersionKind.Exact, IsDirect = true });
        _db.SaveChanges();

        var summary = await _notifications.GetAsync(_userId, default);
        Assert.Equal(["LOW-IN-PROJECT", "CRITICAL-FOLLOWED"], summary.Items.Select(i => i.CanonicalId));
        Assert.Contains("Affects api: mypkg 1.0.0 (fixed in 2.0.0)", summary.Items[0].Reason);
    }

    [Fact]
    public async Task List_is_capped_ranked_by_importance_and_reports_the_total()
    {
        Follow("lodash", TechnologyType.Package, Ecosystem.Npm);
        for (var i = 0; i < 15; i++) AddVuln($"HIGH-{i:D2}", "lodash", Severity.High, hoursAgo: i + 1);
        AddVuln("KEV", "lodash", Severity.High, kev: true, hoursAgo: 100);

        var summary = await _notifications.GetAsync(_userId, default);
        Assert.Equal(NotificationService.MaxItems, summary.Items.Count);
        Assert.Equal(16, summary.TotalRelevant);
        Assert.Equal(16, summary.UnreadCount);
        Assert.Equal("KEV", summary.Items[0].CanonicalId);
    }

    [Fact]
    public async Task Opening_the_bell_marks_items_seen_but_keeps_them_listed()
    {
        Follow("lodash", TechnologyType.Package, Ecosystem.Npm);
        AddVuln("HIGH", "lodash", Severity.High);

        var after = await _notifications.MarkAllReadAsync(_userId, default);
        Assert.Equal(0, after.UnreadCount);
        var item = Assert.Single(after.Items);
        Assert.False(item.IsNew);

        AddVuln("NEWER", "lodash", Severity.Critical, hoursAgo: 0);
        var later = await _notifications.GetAsync(_userId, default);
        Assert.Equal(1, later.UnreadCount);
        Assert.Equal("NEWER", later.Items[0].CanonicalId);
    }
}
